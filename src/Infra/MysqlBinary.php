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
 * The child's stderr is redirected to a temp file rather than drained from a
 * pipe: stream_select() fails on proc_open() descriptors under Windows, so
 * there is no portable way to drain both pipes concurrently. mysqldump output
 * is far larger than the 64 KB a pipe holds, which is why the stdout pipe is
 * still read to EOF rather than left full.
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

        // Redirect stderr to a temp file rather than a pipe. stream_select()
        // fails on proc_open() descriptors under Windows, so concurrent pipe
        // draining is not possible there. A temp file avoids the stderr
        // pipe-buffer deadlock entirely.
        $stderrFile = tempnam(sys_get_temp_dir(), 'mysqldump-stderr');
        if ($stderrFile === false) {
            gzclose($output);
            throw new RuntimeException('Unable to create temporary file for stderr.');
        }

        $pipes = [];
        $process = $this->start($arguments, [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['file', $stderrFile, 'w'],
        ], $pipes);

        // Close stdin immediately — mysqldump never reads from stdin.
        fclose($pipes[0]);

        $bytes = 0;

        while (!feof($pipes[1])) {
            $chunk = fread($pipes[1], self::CHUNK_BYTES);
            if ($chunk === false) {
                break;
            }

            if ($chunk !== '') {
                if (gzwrite($output, $chunk) === false) {
                    gzclose($output);
                    @unlink($stderrFile);
                    $this->finish($process, $pipes, 'writing the dump');
                    throw new RuntimeException(sprintf('Failed writing to "%s".', $outputPath));
                }
                $bytes += strlen($chunk);
            }
        }

        gzclose($output);
        fclose($pipes[1]);

        $status = $this->finish($process, $pipes, 'dumping');

        $errors = file_get_contents($stderrFile);
        @unlink($stderrFile);

        if ($status !== 0) {
            @unlink($outputPath);
            throw new RuntimeException(
                sprintf('%s exited %d: %s', $this->binary, $status, trim($errors === false ? '' : $errors))
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

        // Redirect stderr to a temp file rather than a pipe. stream_select()
        // fails on proc_open() descriptors under Windows, so concurrent pipe
        // draining is not possible there. A temp file avoids the stderr
        // pipe-buffer deadlock entirely.
        $stderrFile = tempnam(sys_get_temp_dir(), 'mysql-stderr');
        if ($stderrFile === false) {
            gzclose($input);
            throw new RuntimeException('Unable to create temporary file for stderr.');
        }

        $pipes = [];
        $process = $this->start($arguments, [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['file', $stderrFile, 'w'],
        ], $pipes);

        $bytes = 0;

        while (!gzeof($input)) {
            $chunk = gzread($input, self::CHUNK_BYTES);
            if ($chunk === false || $chunk === '') {
                break;
            }

            $this->writeAll($pipes[0], $chunk);
            $bytes += strlen($chunk);
        }

        gzclose($input);
        fclose($pipes[0]);
        unset($pipes[0]);

        // stdin is closed, so the client will now finish and exit: it is safe
        // to go back to blocking reads and collect whatever is left.
        stream_set_blocking($pipes[1], true);
        $stdout = stream_get_contents($pipes[1]);
        fclose($pipes[1]);
        unset($pipes[1]);

        $status = $this->finish($process, $pipes, 'restoring');

        $errors = file_get_contents($stderrFile);
        @unlink($stderrFile);

        if ($status !== 0) {
            throw new RuntimeException(
                sprintf('%s exited %d: %s', $this->binary, $status, trim($errors === false ? '' : $errors))
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
            $this->environment(),
            ['bypass_shell' => true]
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

        if (PHP_OS_FAMILY === 'Windows') {
            $env = getenv();
            $env['PATH'] = is_string($path) && $path !== '' ? $path : 'C:\Windows\system32;C:\Windows';
            $env['HOME'] = is_string($home) && $home !== '' ? $home : 'C:\Users\Default';
            $env['MYSQL_PWD'] = $this->password;

            return $env;
        }

        return [
            'PATH' => is_string($path) && $path !== ''
                ? $path
                : '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
            'HOME' => is_string($home) && $home !== '' ? $home : '/root',
            'MYSQL_PWD' => $this->password,
        ];
    }
}
