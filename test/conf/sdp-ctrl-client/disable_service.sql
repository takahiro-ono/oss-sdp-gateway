--
-- Database: `sdp_test`
--
USE `sdp_test`;

UPDATE `sdp_test`.`service_gateway` SET `enabled` = '0' 
WHERE `service_gateway`.`service_id` = 1;

