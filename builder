#! /usr/bin/env node

var fs         = require('fs');
var path       = require('path');
var util       = require('util');
var handlebars = require('handlebars');
var log        = console.log;
var ins        = function () {
  return Array.prototype.slice.call(arguments).map(function (arg){
    return util.inspect(arg, {depth: null});
  }).join('\n');
};

Array.prototype.flatten = function () {
  return this.reduce(function (ret, value) {
    return ret.concat(value instanceof Array ? value.flatten() : value);
  }, []);
};

var parseEntity = function (entity) {
  if (entity.match(/((?:(?:\d{1,3}).?){4}\/\d{1,2})/))
    return {type: 'ip', value: entity};
  if (entity.match(/([\w\d\-_]+)/))
    return {type: 'group', value: entity};
};

var parseProtocol = function (entity) {
  var mapping = {t: 'tcp', u: 'udp', i: 'icmp'};
  return mapping[entity];
};

var parsePort = function (entity) {
  var portRange = entity.split('-');
  if (portRange.length == 1)
    return {from: portRange[0], to: portRange[0]};
  return {from: portRange[0], to: portRange[1]};
};

var makeDescriptor = function (protocols, source, destination, ports) {
  return protocols.map(function (protocol) {
    return ports.map(function (port) {
      return {
        protocol: parseProtocol(protocol),
        source: parseEntity(source),
        destination: parseEntity(destination),
        port: protocol == 'i' ? {from: -1, to: -1}:parsePort(port)
      };
    });
  });
};

var lines       = fs.readFileSync(process.argv[2], {encoding: 'utf8'}).split('\n');
var tokens      = lines.map(function (line) { return line.replace(/\s+/gi, ' ').split(' '); });
var descriptors = tokens.map(function (tokens) {
  if (tokens[0] == '#')
    return [];
  return makeDescriptor(
    tokens[0].split(''),
    tokens[1],
    tokens[3],
    (tokens[4] ? tokens[4]:'0-65535').split(',')
  );
}).flatten();

//TODO check correctnes (i.e. source and destination can't both have type of 'ip')

var rules = descriptors.map(function (descriptor) {
  var ret = [];
  if (descriptor.destination.type == 'group')
    ret.push({target: descriptor.destination.value, direction: 'in', port: descriptor.port, address: descriptor.source, protocol: descriptor.protocol});
  if (descriptor.source.type == 'group')
    ret.push({target: descriptor.source.value, direction: 'out', port: descriptor.port, address: descriptor.destination, protocol: descriptor.protocol});
  return ret;
}).flatten();

var condencedRules = rules.reduce(function (ret, rule) {
  var defaultDescription = 'auto generated group';
  if (!ret[rule.target])
    ret[rule.target] = {};
  ret[rule.target].description = defaultDescription;
  if (!ret[rule.target][rule.direction])
    ret[rule.target][rule.direction] = [];
  var ruleObj = {protocol: rule.protocol, from: rule.port.from, to: rule.port.to, address: rule.address.value};
  if (rule.address.type == 'group') {
    ruleObj.description = defaultDescription;
    ruleObj.group = true;
  }
  ret[rule.target][rule.direction].push(ruleObj);
  return ret;
}, {});

var tpl = fs.readFileSync(process.argv[3], {encoding: 'utf8'});
fs.writeFileSync(path.basename(process.argv[3], '.in'), handlebars.compile(tpl)(condencedRules));
