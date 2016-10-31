-- phpMyAdmin SQL Dump
-- version 4.0.10deb1
-- http://www.phpmyadmin.net
--
-- Host: localhost
-- Generation Time: Jul 18, 2016 at 08:23 AM
-- Server version: 5.5.49-0ubuntu0.14.04.1
-- PHP Version: 5.5.9-1ubuntu4.17

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;

--
-- Database: `sdp_test`
--
USE `sdp_test`;

-- --------------------------------------------------------

--
-- Table structure for table `connections`
--

CREATE TABLE IF NOT EXISTS `connections` (
  `gateway_sdpid` int(11) NOT NULL,
  `client_sdpid` int(11) NOT NULL,
  `start_timestamp` bigint(20) NOT NULL,
  `end_timestamp` bigint(20) NOT NULL,
  `source_ip` tinytext COLLATE utf8_bin NOT NULL,
  `source_port` int(11) NOT NULL,
  `destination_ip` tinytext COLLATE utf8_bin NOT NULL,
  `destination_port` int(11) NOT NULL,
  PRIMARY KEY (`gateway_sdpid`,`client_sdpid`,`start_timestamp`,`source_port`),
  KEY `gateway_sdpid` (`gateway_sdpid`),
  KEY `client_sdpid` (`client_sdpid`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

-- --------------------------------------------------------

--
-- Table structure for table `controller`
--

DROP TABLE IF EXISTS `controller`;
CREATE TABLE IF NOT EXISTS `controller` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(1024) COLLATE utf8_bin NOT NULL,
  `address` varchar(4096) COLLATE utf8_bin NOT NULL COMMENT 'ip or url',
  `port` int(11) NOT NULL,
  `sdpid_id` int(11) NOT NULL,
  `gateway_id` int(11) DEFAULT NULL,
  `service_id` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `service_id` (`service_id`),
  KEY `gateway_id` (`gateway_id`),
  KEY `sdpid_id` (`sdpid_id`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 COLLATE=utf8_bin AUTO_INCREMENT=2 ;

--
-- RELATIONS FOR TABLE `controller`:
--   `service_id`
--       `service` -> `id`
--   `gateway_id`
--       `gateway` -> `id`
--   `sdpid_id`
--       `sdpid` -> `id`
--

--
-- Dumping data for table `controller`
--

INSERT INTO `controller` (`id`, `name`, `address`, `port`, `sdpid_id`, `gateway_id`, `service_id`) VALUES
(1, 'ctrl1', '127.0.0.1', 5000, 111, 2, 1);

-- --------------------------------------------------------

--
-- Table structure for table `environment`
--

DROP TABLE IF EXISTS `environment`;
CREATE TABLE IF NOT EXISTS `environment` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(1024) COLLATE utf8_bin NOT NULL,
  `mobile` tinyint(1) NOT NULL,
  `os_group` enum('Android','iOS','Windows','OSX','Linux') COLLATE utf8_bin NOT NULL,
  `os_version` varchar(1024) COLLATE utf8_bin NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_bin AUTO_INCREMENT=1 ;

-- --------------------------------------------------------

--
-- Table structure for table `gateway`
--

DROP TABLE IF EXISTS `gateway`;
CREATE TABLE IF NOT EXISTS `gateway` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(1024) COLLATE utf8_bin NOT NULL,
  `address` varchar(1024) COLLATE utf8_bin NOT NULL COMMENT 'ip or url',
  `port` int(11) DEFAULT NULL,
  `sdpid_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `sdpid_id` (`sdpid_id`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 COLLATE=utf8_bin AUTO_INCREMENT=3 ;

--
-- RELATIONS FOR TABLE `gateway`:
--   `sdpid_id`
--       `sdpid` -> `id`
--

--
-- Dumping data for table `gateway`
--

INSERT INTO `gateway` (`id`, `name`, `address`, `port`, `sdpid_id`) VALUES
(1, 'gate2', '127.0.0.1', NULL, 222),
(2, 'gate3', '192.168.1.36', NULL, 444);

-- --------------------------------------------------------

--
-- Table structure for table `gateway_controller`
--

DROP TABLE IF EXISTS `gateway_controller`;
CREATE TABLE IF NOT EXISTS `gateway_controller` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `gateway_id` int(11) NOT NULL,
  `controller_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `controller_id` (`controller_id`),
  KEY `gateway_id` (`gateway_id`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 COLLATE=utf8_bin AUTO_INCREMENT=3 ;

--
-- RELATIONS FOR TABLE `gateway_controller`:
--   `controller_id`
--       `controller` -> `id`
--   `gateway_id`
--       `gateway` -> `id`
--

--
-- Dumping data for table `gateway_controller`
--

INSERT INTO `gateway_controller` (`id`, `gateway_id`, `controller_id`) VALUES
(1, 1, 1),
(2, 2, 1);

-- --------------------------------------------------------

--
-- Table structure for table `sdpid`
--

DROP TABLE IF EXISTS `sdpid`;
CREATE TABLE IF NOT EXISTS `sdpid` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `type` enum('client','gateway','controller') COLLATE utf8_bin NOT NULL DEFAULT 'client',
  `country` varchar(128) COLLATE utf8_bin NOT NULL,
  `state` varchar(128) COLLATE utf8_bin NOT NULL,
  `locality` varchar(128) COLLATE utf8_bin NOT NULL,
  `org` varchar(128) COLLATE utf8_bin NOT NULL,
  `org_unit` varchar(128) COLLATE utf8_bin DEFAULT NULL,
  `alt_name` varchar(128) COLLATE utf8_bin DEFAULT NULL,
  `email` varchar(128) COLLATE utf8_bin DEFAULT NULL,
  `encrypt_key` varchar(2048) COLLATE utf8_bin DEFAULT NULL,
  `hmac_key` varchar(2048) COLLATE utf8_bin DEFAULT NULL,
  `serial` varchar(32) COLLATE utf8_bin NOT NULL,
  `last_cred_update` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `cred_update_due` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `user_id` int(11) DEFAULT NULL,
  `environment_id` int(11) DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`),
  KEY `environment_id` (`environment_id`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 COLLATE=utf8_bin AUTO_INCREMENT=55556 ;

--
-- RELATIONS FOR TABLE `sdpid`:
--   `user_id`
--       `user` -> `id`
--   `environment_id`
--       `environment` -> `id`
--

--
-- Dumping data for table `sdpid`
--

INSERT INTO `sdpid` (`id`, `type`, `country`, `state`, `locality`, `org`, `org_unit`, `alt_name`, `email`, `encrypt_key`, `hmac_key`, `serial`, `last_cred_update`, `cred_update_due`, `user_id`, `environment_id`) VALUES
(111, 'controller', 'US', 'Virginia', 'Waterford', 'Waverley Labs, LLC', 'R&D', NULL, 'email@email.com', NULL, NULL, '0', '0000-00-00 00:00:00', '0000-00-00 00:00:00', NULL, NULL),
(333, 'client', 'US', 'Virginia', 'Leesburg', 'Waverley Labs, LLC', 'R&D', NULL, 'email@email.com', 'Xpee90NZMvAyKJ5fxQIRALNdETK8w3pTR60NJBJy5Bw=', 'PRxnFcl+rUFpg2R6sHyuAiCs0imvVP1wn0Qweqokd9XZweOwmRABWtpxehbahY7QuMKhbE690ln5E6VtqQJBAIOEtHE+oqFe5kPL3oUGP+y+YvIFcr/iWYhmRJ+HHBRjiToNQIUO7n2xPehBlOseFYRT27XK0Cyn6BtHBCM21Wc=', '00AF8F8EAC509B9321', '2016-07-14 21:30:08', '2016-08-14 04:00:00', 1, NULL),
(222, 'gateway', 'US', 'Virginia', 'Waterford', 'Waverley Labs, LLC', 'R&D', NULL, 'email@email.com', 'z8ngq6MaidxxStiUHk0CECm0CBSuYUvyD8zb99oliV4=', '60stItDmZeQNWz8ODvz1fdchhYp3h+finZieSO6vKUdSSUkPyglKVv9heFc23Yh7vbRp+jvX2eIN+rAa8QJBAOJ7GALaqWPbE/DUu+UIzLbJvNzvCPLj+iUe/td+ot6jVNGOMrIitsEt1r9gf66eGq6WZJ6lY60USIndz0NrdMA=', 'AF9F9DBA208EF44F', '2016-07-14 21:44:15', '2016-08-14 04:00:00', NULL, NULL),
(444, 'gateway', 'US', 'Virginia', 'Leesburg', 'Waverley Labs, LLC', 'R&D', NULL, 'email@email.com', 'cRUukYanhaY7pcbS0QIRAOxuP4MfXB1YcLN1gWxEPD8=', 'wYnVbpwtCgfsxJb7zmRURPN1pw9OPKFBRP77pz8ILY2Ey4l5tqvPV8Q0dPGN5NkF6RMuYd7r5i+PmEEep/sCQC/ejhPAGPrrgLAc1/OAVYSTh6lLYx4N7vjJqSEnmhy/FQVAvNv2WWoOT0GCyNjWfoO16W2hFtC++1+5I8AIuy8=', '00AF8F8EAC509B9323', '2016-07-14 21:28:40', '2016-08-14 04:00:00', NULL, NULL),
(555, 'client', 'US', 'Florida', 'Miami', 'Waverley Labs, LLC', 'R&D', NULL, 'email@email.com', 'someencryptkey', 'somehmackey', '00AF8F8EAC509B9324', '0000-00-00 00:00:00', '0000-00-00 00:00:00', 2, NULL);

-- --------------------------------------------------------

--
-- Table structure for table `sdpid_service`
--

DROP TABLE IF EXISTS `sdpid_service`;
CREATE TABLE IF NOT EXISTS `sdpid_service` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `sdpid_id` int(11) NOT NULL,
  `service_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `service_id` (`service_id`),
  KEY `sdpid_id` (`sdpid_id`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 COLLATE=utf8_bin AUTO_INCREMENT=7 ;

--
-- RELATIONS FOR TABLE `sdpid_service`:
--   `service_id`
--       `service` -> `id`
--   `sdpid_id`
--       `sdpid` -> `id`
--

--
-- Dumping data for table `sdpid_service`
--

INSERT INTO `sdpid_service` (`id`, `sdpid_id`, `service_id`) VALUES
(1, 333, 1),
(2, 333, 3),
(3, 333, 4),
(4, 555, 2),
(5, 555, 1),
(6, 444, 1);

-- --------------------------------------------------------

--
-- Table structure for table `service`
--

DROP TABLE IF EXISTS `service`;
CREATE TABLE IF NOT EXISTS `service` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(1024) COLLATE utf8_bin NOT NULL,
  `description` varchar(4096) COLLATE utf8_bin NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 COLLATE=utf8_bin AUTO_INCREMENT=5 ;

--
-- Dumping data for table `service`
--

INSERT INTO `service` (`id`, `name`, `description`) VALUES
(1, 'SDP Controller', 'What it sounds like'),
(2, 'gate2 ssh', 'ssh service on gate2'),
(3, 'mail', 'mail server'),
(4, 'gate2.com', 'website');

-- --------------------------------------------------------

--
-- Table structure for table `service_gateway`
--

DROP TABLE IF EXISTS `service_gateway`;
CREATE TABLE IF NOT EXISTS `service_gateway` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `service_id` int(11) NOT NULL,
  `gateway_id` int(11) NOT NULL,
  `protocol_port` char(12) COLLATE utf8_bin NOT NULL COMMENT 'tcp/22  protocol and port service listens on',
  `nat_access` varchar(128) COLLATE utf8_bin DEFAULT NULL COMMENT '1.1.1.1:22   for NAT_ACCESS field of access stanza, combines internal address and external (firewall) port',
  PRIMARY KEY (`id`),
  KEY `service_id` (`service_id`),
  KEY `gateway_id` (`gateway_id`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 COLLATE=utf8_bin AUTO_INCREMENT=5 ;

--
-- RELATIONS FOR TABLE `service_gateway`:
--   `service_id`
--       `service` -> `id`
--   `gateway_id`
--       `gateway` -> `id`
--

--
-- Dumping data for table `service_gateway`
--

INSERT INTO `service_gateway` (`id`, `service_id`, `gateway_id`, `protocol_port`, `nat_access`) VALUES
(1, 1, 1, 'tcp/5000', NULL),
(2, 2, 1, 'tcp/22', NULL),
(3, 3, 1, 'tcp/25', '192.168.1.250:54321'),
(4, 4, 1, 'tcp/80', '192.168.1.201:80');

-- --------------------------------------------------------

--
-- Table structure for table `user`
--

DROP TABLE IF EXISTS `user`;
CREATE TABLE IF NOT EXISTS `user` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `last_name` varchar(128) COLLATE utf8_bin NOT NULL,
  `first_name` varchar(128) COLLATE utf8_bin NOT NULL,
  `country` varchar(128) COLLATE utf8_bin DEFAULT NULL,
  `state` varchar(128) COLLATE utf8_bin DEFAULT NULL,
  `locality` varchar(128) COLLATE utf8_bin DEFAULT NULL,
  `org` varchar(128) COLLATE utf8_bin DEFAULT NULL,
  `org_unit` varchar(128) COLLATE utf8_bin DEFAULT NULL,
  `alt_name` varchar(128) COLLATE utf8_bin DEFAULT NULL,
  `email` varchar(128) COLLATE utf8_bin NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB  DEFAULT CHARSET=utf8 COLLATE=utf8_bin AUTO_INCREMENT=3 ;

--
-- Dumping data for table `user`
--

INSERT INTO `user` (`id`, `last_name`, `first_name`, `country`, `state`, `locality`, `org`, `org_unit`, `alt_name`, `email`) VALUES
(1, 'Last', 'First', '', '', '', '', '', '', 'email@email.com'),
(2, 'Otherlast', 'Otherfirst', 'US', 'Florida', 'Miami', 'Waverley Labs, LLC', 'R&D', NULL, 'email@email.com');

-- --------------------------------------------------------

--
-- Constraints for dumped tables
--

--
-- Constraints for table `controller`
--
ALTER TABLE `controller`
  ADD CONSTRAINT `controller_ibfk_2` FOREIGN KEY (`service_id`) REFERENCES `service` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT `controller_ibfk_3` FOREIGN KEY (`gateway_id`) REFERENCES `gateway` (`id`) ON DELETE SET NULL ON UPDATE CASCADE,
  ADD CONSTRAINT `controller_ibfk_4` FOREIGN KEY (`sdpid_id`) REFERENCES `sdpid` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `gateway`
--
ALTER TABLE `gateway`
  ADD CONSTRAINT `gateway_ibfk_1` FOREIGN KEY (`sdpid_id`) REFERENCES `sdpid` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `gateway_controller`
--
ALTER TABLE `gateway_controller`
  ADD CONSTRAINT `gateway_controller_ibfk_2` FOREIGN KEY (`controller_id`) REFERENCES `controller` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT `gateway_controller_ibfk_3` FOREIGN KEY (`gateway_id`) REFERENCES `gateway` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `sdpid`
--
ALTER TABLE `sdpid`
  ADD CONSTRAINT `sdpid_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `user` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT `sdpid_ibfk_2` FOREIGN KEY (`environment_id`) REFERENCES `environment` (`id`) ON DELETE SET NULL ON UPDATE CASCADE;

--
-- Constraints for table `sdpid_service`
--
ALTER TABLE `sdpid_service`
  ADD CONSTRAINT `sdpid_service_ibfk_2` FOREIGN KEY (`service_id`) REFERENCES `service` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT `sdpid_service_ibfk_3` FOREIGN KEY (`sdpid_id`) REFERENCES `sdpid` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

--
-- Constraints for table `service_gateway`
--
ALTER TABLE `service_gateway`
  ADD CONSTRAINT `service_gateway_ibfk_1` FOREIGN KEY (`service_id`) REFERENCES `service` (`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  ADD CONSTRAINT `service_gateway_ibfk_2` FOREIGN KEY (`gateway_id`) REFERENCES `gateway` (`id`) ON DELETE CASCADE ON UPDATE CASCADE;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;

