--
-- Database: `sdp_test`
--
USE `sdp_test`;

UPDATE `sdp_test`.`sdpid_service` SET `enabled` = '0' 
WHERE `sdpid_service`.`sdpid` = 333 AND
      `sdpid_service`.`service_id` = 1;

