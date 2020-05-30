/*
Navicat MySQL Data Transfer

Source Server         : local
Source Server Version : 50720
Source Host           : localhost:3306
Source Database       : securitydemo

Target Server Type    : MYSQL
Target Server Version : 50720
File Encoding         : 65001

Date: 2020-05-29 16:14:25
*/

SET FOREIGN_KEY_CHECKS=0;

-- ----------------------------
-- Table structure for se_permission
-- ----------------------------
DROP TABLE IF EXISTS `se_permission`;
CREATE TABLE `se_permission` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `permissionValue` varchar(255) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8;

-- ----------------------------
-- Records of se_permission
-- ----------------------------
INSERT INTO `se_permission` VALUES ('1', 'read');
INSERT INTO `se_permission` VALUES ('2', 'write');

-- ----------------------------
-- Table structure for se_role
-- ----------------------------
DROP TABLE IF EXISTS `se_role`;
CREATE TABLE `se_role` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8;

-- ----------------------------
-- Records of se_role
-- ----------------------------
INSERT INTO `se_role` VALUES ('1', 'admin');

-- ----------------------------
-- Table structure for se_role_permission
-- ----------------------------
DROP TABLE IF EXISTS `se_role_permission`;
CREATE TABLE `se_role_permission` (
  `roleId` int(11) DEFAULT NULL,
  `permissionId` int(11) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ----------------------------
-- Records of se_role_permission
-- ----------------------------
INSERT INTO `se_role_permission` VALUES ('1', '1');
INSERT INTO `se_role_permission` VALUES ('1', '2');

-- ----------------------------
-- Table structure for se_user
-- ----------------------------
DROP TABLE IF EXISTS `se_user`;
CREATE TABLE `se_user` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(255) NOT NULL,
  `password` varchar(255) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8;

-- ----------------------------
-- Records of se_user
-- ----------------------------
INSERT INTO `se_user` VALUES ('1', 'siyang', '$2a$10$utOqKaFyWaKVbsg5ScEz7uvvMPsDbt6z/1hi6dyQgR80uGkEK5.ga');
INSERT INTO `se_user` VALUES ('2', 'lisi', '$2a$10$utOqKaFyWaKVbsg5ScEz7uvvMPsDbt6z/1hi6dyQgR80uGkEK5.ga');

-- ----------------------------
-- Table structure for se_user_role
-- ----------------------------
DROP TABLE IF EXISTS `se_user_role`;
CREATE TABLE `se_user_role` (
  `userId` int(11) DEFAULT NULL,
  `roleId` int(11) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- ----------------------------
-- Records of se_user_role
-- ----------------------------
INSERT INTO `se_user_role` VALUES ('1', '1');
