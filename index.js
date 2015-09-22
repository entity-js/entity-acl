/**
 *  ____            __        __
 * /\  _`\         /\ \__  __/\ \__
 * \ \ \L\_\    ___\ \ ,_\/\_\ \ ,_\  __  __
 *  \ \  _\L  /' _ `\ \ \/\/\ \ \ \/ /\ \/\ \
 *   \ \ \L\ \/\ \/\ \ \ \_\ \ \ \ \_\ \ \_\ \
 *    \ \____/\ \_\ \_\ \__\\ \_\ \__\\/`____ \
 *     \/___/  \/_/\/_/\/__/ \/_/\/__/ `/___/> \
 *                                        /\___/
 *                                        \/__/
 *
 * Entity ACL
 */

var path = require('path'),
    fs = require('fs'),
    loader = require('nsloader');

// Allow access to the Entity ACL index file.
loader.register('EntityACL', function () {
  'use strict';

  return path.resolve(path.join(__dirname, 'index.js'));
});

// Allow access to anything after 'EntityACL'.
loader.register('EntityACL/*', function (ns) {
  'use strict';

  var filename = path.join(__dirname, 'lib', ns.substring('EntityACL/'.length));
  if (fs.existsSync(filename + '.js')) {
    return filename + '.js';
  } else if (fs.existsSync(path.join(filename, 'index.js'))) {
    return path.join(filename, 'index.js');
  }

  return false;
});

module.exports = require('./lib');
