-- phpMyAdmin SQL Dump
-- version 3.3.4
-- http://www.phpmyadmin.net
--
-- Host: localhost
-- Generation Time: Jul 19, 2010 at 05:06 AM
-- Server version: 5.1.48
-- PHP Version: 5.3.2

SET SQL_MODE="NO_AUTO_VALUE_ON_ZERO";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;

--
-- Database: `b3_v4`
--

-- --------------------------------------------------------

--
-- Table structure for table `badrcon`
--

CREATE TABLE IF NOT EXISTS `badrcon` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `ip` varchar(20) NOT NULL,
  `cnt` int(11) NOT NULL,
  `ban` tinyint(1) NOT NULL,
  `client` varchar(50) NOT NULL,
  `modified_date` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `immune` tinyint(1) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM  DEFAULT CHARSET=latin1 COMMENT='Used for badrcon.py' AUTO_INCREMENT=32 ;

--
-- Dumping data for table `badrcon`
--

INSERT INTO `badrcon` (`id`, `ip`, `cnt`, `ban`, `client`, `modified_date`, `immune`) VALUES
(1, '0.0.0.0', 0, 0, 'None', '2010-07-12 00:00:00', 1),
(22, '192.168.1.100', 0, 0, '', '2010-07-18 09:25:08', 1);
