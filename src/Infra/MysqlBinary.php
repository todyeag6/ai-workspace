<?php

declare(strict_types=1);

namespace App\Infra;

use RuntimeException;

/**
 * Runs the mysqldump / mysql binaries and streams gzip in or out of them.
 *
 * SECURITY: the command is handed to proc_open as an ARRAY, never as a
 * string. PHP then execs the binary directly with execvp semantics, so no
 * shell ever sees the arguments and there is nothing to quote, escape or get
 * wrong. A database name or output path containing shell metacharacters is
 * just a database name or output path. This is the reason the class exists
 * rather than a one-line exec() in each script.
 *
 * The password is passed through the MYSQL_PWD environment variable of the
 * child process rather than as --password=..., which keeps it out of the
 * process table where any other user on the host could read it with ps.
 *
 * The child's stdout/stderr are drained on every loop iteration while data is
 * being pumped. Filling a pipe buffer that nobody is reading is the classic
 * way to deadlock proc_open, and mysqldump output is far larger than the 64 KB
 * a pipe holds.
 */
final class MysqlBinary
{
    private const CHUNK_BYTES = 65536;

    public function __construct(
        private readonly string $binary,
        private readonly string $password
    ) {
    }

    /**
     * Runs the binary and writes everything it prints to a gzip file.
     *
     * @param  list<string> $arguments
     * @return int bytes of uncompressed SQL captured
     */
    public function dumpToGzip(array $arguments, string $outputPath): int
    {
        $this->ensureDirectory(dirname($outputPath));

        $output = gzopen($outputPath, 'wb6');
        if ($output === false) {
            throw new RuntimeException(sprintf('Unable to open "%s" for writing.', $outputPath));
        }

        $pipes = [];
        $process = $this->start($arguments, [
            0 => ['file', '/dev/null', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ], $pipes);

        stream_set_blocking($pipes[2], false);

        $bytes = 0;
        $errors = '';

        while (!feof($pipes[1])) {
            $chunk = fread($pipes[1], self::CHUNK_BYTES);
            if ($chunk === false) {
                break;
            }

            if ($chunk !== '') {
                if (gzwrite($output, $chunk) === false) {
                    gzclose($output);
                    $this->finish($process, $pipes, 'writing the dump');
                    throw new RuntimeException(sprintf('Failed writing to "%s".', $outputPath));
                }
                $bytes += strlen($chunk);
            }

            $errors .= $this->drain($pipes[2]);
        }

        $errors .= $this->drain($pipes[2]);
        gzclose($output);

        $status = $this->finish($process, $pipes, 'dumping');
        if ($status !== 0) {
            @unlink($outputPath);
            throw new RuntimeException(
                sprintf('%s exited %d: %s', $this->binary, $status, trim($errors))
            );
        }

        if ($bytes === 0) {
            @unlink($outputPath);
            throw new RuntimeException(sprintf('%s produced an empty dump.', $this->binary));
        }

        return $bytes;
    }

    /**
     * Decompresses a gzip file straight into the binary's stdin.
     *
     * @param  list<string> $arguments
     * @return int bytes of uncompressed SQL fed to the client
     */
    public function loadFromGzip(array $arguments, string $inputPath): int
    {
        if (!is_file($inputPath)) {
            throw new RuntimeException(sprintf('Dump "%s" does not exist.', $inputPath));
        }

        $input = gzopen($inputPath, 'rb');
        if ($input === false) {
            throw new RuntimeException(sprintf('Unable to open "%s" for reading.', $inputPath));
        }

        $pipes = [];
        $process = $this->start($arguments, [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ], $pipes);

        stream_set_blocking($pipes[1], false);
        stream_set_blocking($pipes[2], false);

        $bytes = 0;
        $errors = '';

        while (!gzeof($input)) {
            $chunk = gzread($input, self::CHUNK_BYTES);
            if ($chunk === false || $chunk === '') {
                break;
            }

            $this->writeAll($pipes[0], $chunk);
            $bytes += strlen($chunk);

            $this->drain($pipes[1]);
            $errors .= $this->drain($pipes[2]);
        }

        gzclose($input);
        fclose($pipes[0]);
        unset($pipes[0]);

        // stdin is closed, so the client will now finish and exit: it is safe
        // to go back to blocking reads and collect whatever is left.
        stream_set_blocking($pipes[1], true);
        stream_set_blocking($pipes[2], true);
        $errors .= $this->drain($pipes[2]);

        $status = $this->finish($process, $pipes, 'restoring');
        if ($status !== 0) {
            throw new RuntimeException(
                sprintf('%s exited %d: %s', $this->binary, $status, trim($errors))
            );
        }

        return $bytes;
    }

    /**
     * @param  list<string>                                 $arguments
     * @param  array<int, array{0: string, 1: string, 2?: string}> $descriptors
     * @param  array<int, resource>                         $pipes
     * @return resource
     */
    private function start(array $arguments, array $descriptors, array &$pipes)
    {
        $process = proc_open(
            array_merge([$this->binary], $arguments),
            $descriptors,
            $pipes,
            null,
            $this->environment()
        );

        if (!is_resource($process)) {
            throw new RuntimeException(sprintf('Unable to start "%s".', $this->binary));
        }

        return $process;
    }

    /**
     * @param resource            $process
     * @param array<int, resource> $pipes
     */
    private function finish($process, array $pipes, string $stage): int
    {
        foreach ($pipes as $pipe) {
            if (is_resource($pipe)) {
                fclose($pipe);
            }
        }

        $status = proc_close($process);

        if ($status === -1) {
            throw new RuntimeException(sprintf('Lost track of "%s" while %s.', $this->binary, $stage));
        }

        return $status;
    }

    /**
     * @param resource $pipe
     */
    private function drain($pipe): string
    {
        $contents = stream_get_contents($pipe);

        return $contents === false ? '' : $contents;
    }

    /**
     * fwrite on a pipe may accept fewer bytes than offered, so keep going
     * until the whole chunk is through.
     *
     * @param resource $pipe
     */
    private function writeAll($pipe, string $data): void
    {
        $offset = 0;
        $length = strlen($data);

        while ($offset < $length) {
            $written = fwrite($pipe, substr($data, $offset));
            if ($written === false || $written === 0) {
                throw new RuntimeException(sprintf('Failed piping SQL into "%s".', $this->binary));
            }
            $offset += $written;
        }
    }

    private function ensureDirectory(string $directory): void
    {
        if (is_dir($directory)) {
            return;
        }

        if (!mkdir($directory, 0o775, true) && !is_dir($directory)) {
            throw new RuntimeException(sprintf('Unable to create directory "%s".', $directory));
        }
    }

    /**
     * A deliberately small environment for the child process.
     *
     * @return array<string, string>
     */
    private function environment(): array
    {
        $path = getenv('PATH');
        $home = getenv('HOME');

        return [
            'PATH' => is_string($path) && $path !== ''
                ? $path
                : '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
            'HOME' => is_string($home) && $home !== '' ? $home : '/root',
            'MYSQL_PWD' => $this->password,
        ];
    }
}
