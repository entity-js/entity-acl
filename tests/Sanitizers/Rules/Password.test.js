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

var test = require('unit.js'),
    loader = require('nsloader'),
    Sanitizers = loader('Entity/Sanitizers'),
    EInvalidValue = loader('Entity/Sanitizers/Errors/EInvalidValue');

describe('entityACL/Sanitizers/Rules/Password', function () {

  'use strict';

  it('shouldThrowErrorIfNotString', function (done) {

    var sanitizers = new Sanitizers();
    sanitizers.register(
      'password',
      loader('EntityACL/Sanitizers/Rules/Password')
    );

    sanitizers.sanitize(function (err, orig, value) {

      test.object(err)
        .isInstanceOf(EInvalidValue)
        .hasKey('value', orig);

      done();

    }, 'password', false);

  });

  it('shouldHashProvidedValue', function (done) {

    var sanitizers = new Sanitizers();
    sanitizers.register(
      'password',
      loader('EntityACL/Sanitizers/Rules/Password')
    );

    sanitizers.sanitize(function (err, orig, value) {

      test.value(
        err
      ).isNull();

      test.value(
        orig
      ).is('password');

      test.value(
        value
      ).isNot('password');

      var passwordHash = new (require('phpass').PasswordHash)();
      test.bool(
        passwordHash.checkPassword('password', value)
      ).isTrue();

      done();

    }, 'password', 'password');

  });

});
