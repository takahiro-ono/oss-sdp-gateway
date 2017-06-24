--
-- Database: `sdp_test`
--
USE `sdp_test`;

ALTER TABLE `controller` DROP FOREIGN KEY `controller_ibfk_2`; 
ALTER TABLE `controller` ADD CONSTRAINT `controller_ibfk_2` FOREIGN KEY (`service_id`) REFERENCES `service`(`id`) ON DELETE SET NULL ON UPDATE CASCADE;

ALTER TABLE `open_connection` DROP FOREIGN KEY `open_connection_ibfk_3`; 
ALTER TABLE `open_connection` ADD CONSTRAINT `open_connection_ibfk_3` FOREIGN KEY (`service_id`) REFERENCES `service`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

DELETE FROM `sdp_test`.`service` 
WHERE `service`.`id` = 1;
