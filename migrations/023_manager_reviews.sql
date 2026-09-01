CREATE TABLE IF NOT EXISTS `manager_reviews` (
    `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `tenant_id` INT UNSIGNED NOT NULL,
    `manager_task_id` INT UNSIGNED NOT NULL,
    `review_type` ENUM('spec_compliance', 'code_quality') NOT NULL,
    `verdict` ENUM('pass', 'fail', 'approved', 'changes_requested') NOT NULL,
    `findings` JSON NULL,
    `reviewer_model` VARCHAR(128) NULL,
    `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    INDEX `idx_manager_reviews_tenant` (`tenant_id`),
    INDEX `idx_manager_reviews_task` (`manager_task_id`),
    CONSTRAINT `fk_manager_reviews_task` FOREIGN KEY (`manager_task_id`)
        REFERENCES `manager_tasks` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
