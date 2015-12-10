// Licensed under the Apache License. See footer for details.
var OAuth2Strategy = require('passport-oauth').OAuth2Strategy, 
    InternalOAuthError = require('passport-oauth').InternalOAuthError,
    url = require('url'),
    util = require('util');

var PROVIDER = 'ibmid',
    SSO_LOGOUT_URL = 'https://www-947.ibm.com/pkmslogout?page=',
    SSO_AUTHORIZATION_URL = 'https://idaas.ng.bluemix.net/sps/oauth20sp/oauth20/authorize',
    SSO_TOKEN_URL = 'https://idaas.ng.bluemix.net/sps/oauth20sp/oauth20/token',
    SSO_PROFILE_URL = 'https://idaas.ng.bluemix.net/idaas/resources/profile.jsp',
    SSO_REQUESTED_AUTH_POLICY = 'http://www.ibm.com/idaas/authnpolicy/reauth';

function Strategy(options, verify) {
  options = options || {};
  options.authorizationURL = options.authorizationURL || SSO_AUTHORIZATION_URL;
  options.tokenURL = options.tokenURL || SSO_TOKEN_URL;
  options.profileURL = options.profileURL || SSO_PROFILE_URL;
  options.logoutURL = options.logoutURL || SSO_LOGOUT_URL;
  options.policy = options.policy || SSO_REQUESTED_AUTH_POLICY;
  options.scope = options.scope || ['profile'];

  OAuth2Strategy.call(this, options, verify);

  this.name = PROVIDER;

  this._profileURL = options.profileURL;    
  this._policy = options.policy;

  this.logout = function(req, res, url) {
    var logoutURL = options.logoutURL;
    req.session.destroy(function (err) {
      if (err) throw new InternalOAuthError('Failed to logout ', err);
      req.logout();
      res.redirect(logoutURL + url); 
    });
  }
}

util.inherits(Strategy, OAuth2Strategy);

Strategy.prototype.userProfile = function(accessToken, done) {
  var purl = url.parse(this._profileURL);
  purl = url.format(purl);
  this._oauth2.get(purl, accessToken, function (err, body, res) {
      var json;
      
      if (err) {
        if (err.data) {
          try {
            json = JSON.parse(err.data);
          } catch (_) {}
        }
        
        return done(new InternalOAuthError('Failed to fetch user profile', err));
      }
      
      try {
        json = JSON.parse(body);
      } catch (ex) {
        return done(new Error('Failed to parse user profile'));
      }

      var profile = json;
      profile.provider = PROVIDER;

      return done(null, profile);
  });
};



Strategy.prototype.authorizationParams = function(options) {
 var params = {};

  if (options.policy) {
    params.requestedAuthnPolicy = options.policy;
  } else
    params.requestedAuthnPolicy = this._policy;

  return params;
}


module.exports = Strategy;
//-------------------------------------------------------------------------------
// Copyright IBM Corp. 2014
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//-------------------------------------------------------------------------------