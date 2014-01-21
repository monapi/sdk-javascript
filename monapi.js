(function (window) {
    "use strict";

    /**
     *
     ***********************************************************************
     * Alias backbone, underscore and jQuery.
     ***********************************************************************
     *
     */
    var Backbone = window.Backbone;
    var _ = window._;
    var $ = window.$;

    /**
     *
     ***********************************************************************
     * Parse hash helper method used for parsing location.hash.
     ***********************************************************************
     *
     */
    var parseHash = function (hash) {
        var params = {};
        var queryString = hash.substring(1);
        var regex = /([^&=]+)=([^&]*)/g;
        var m;
        while (m = regex.exec(queryString)) {
            params[decodeURIComponent(m[1])] = decodeURIComponent(m[2]);
        }
        return params;
    };

    /**
     ***********************************************************************
     * parse fragment parameters
     ***********************************************************************
     */
    var parseQueryString = function( queryString ) {
        var params = {}, queries, temp, i, l;

        // Split into key/value pairs
        queries = queryString.split("&");

        // Convert the array of strings into an object
        for ( i = 0, l = queries.length; i < l; i++ ) {
            temp = queries[i].split('=');
            params[temp[0]] = temp[1];
        }

        return params;
    };

    var nativeSync = Backbone.sync;



    Backbone.sync = function(method, model, options) {

        var xhr, dfd;

        dfd = $.Deferred();


        options.beforeSend = function (jqxhr, settings) {
            settings.url += settings.url.match(/\?/) ? "&" : "?";
            settings.url += "access_token=" + ($.cookie('access_token'));
        };

        // opts.success and opts.error are resolved against the deferred object
        // instead of the jqXHR object
        if (options) {
            dfd.then(options.success, options.error);
        }

        xhr = nativeSync.call(this, method, model, _.omit(options, 'success', 'error'));

        // success : forward to the deferred
        xhr.done(dfd.resolve);

        // failure : resolve or reject the deferred according to your cases
        xhr.fail(function() {
            console.log('fail');
            $.removeCookie('access_token');
            $.removeCookie('user_id');
            //MonapiOauth.auth();
        });
        
        return dfd.promise();
    };

    /**
     *
     ***********************************************************************
     * Extend Backbone with OAuth functionality.
     ***********************************************************************
     *
     */
    Backbone.OAuth || (Backbone.OAuth = {});

    /**
     ***********************************************************************
     * The base OAuth class.
     ***********************************************************************
     */
    Backbone.OAuth = function (options) {
        /**
         ***********************************************************************
         * Override any default option with the options passed to the constructor.
         ***********************************************************************
         */
        _.extend(this, options);

        /**
         ***********************************************************************
         * Make the onRedirect function publicly available.
         ***********************************************************************
         */
        _.bind(this.onRedirect, this);
        window.OAuthRedirect = this.onRedirect;

        /**
         ***********************************************************************
         * Make the onRedirect function publicly available.
         ***********************************************************************
         */
        //@todo bak bakalım kullanıyor muyum?
        _.bind(this.getAccessToken, this);
        window.getAccessToken = this.getAccessToken;

    };



    /**
     ***********************************************************************
     * Inject methods and properties.
     ***********************************************************************
     */
    _.extend(Backbone.OAuth.prototype, {
        /**
         ***********************************************************************
         * From: http://phpjs.org/functions
         * original by: Kevin van Zonneveld (http://kevin.vanzonneveld.net)
         * improved by: Felix Geisendoerfer (http://www.debuggable.com/felix)
         * example 1: array_key_exists('kevin', {'kevin': 'van Zonneveld'});
         * returns 1: true
         * input sanitation
         ***********************************************************************
         * @return boolean
         */
        array_key_exists: function(key, search) {
            if (!search || (search.constructor !== Array && search.constructor !== Object)) {
                return false;
            }
            return key in search;
        },

        /**
         ***********************************************************************
         * From: http://phpjs.org/functions
         * original by: Kevin van Zonneveld (http://kevin.vanzonneveld.net)
         * improved by: vlado houba
         * input by: Billy
         * bug fixed by: Brett Zamir (http://brett-zamir.me)
         ***********************************************************************
         * @return boolean
         */
        in_array: function(needle, haystack, argStrict) {
            var key = '', strict = !! argStrict;
            if (strict) {
                for (key in haystack) {
                    if (haystack[key] === needle) {
                        return true;
                    }
                }
            } else {
                for (key in haystack) {
                    if (haystack[key] == needle) {
                        return true;
                    }
                }
            }
            return false;
        },

        /**
         ***********************************************************************
         * From: http://phpjs.org/functions
         * original by: Philip Peterson
         * improved by: Kevin van Zonneveld (http://kevin.vanzonneveld.net)
         * improved by: Brett Zamir (http://brett-zamir.me)
         * improved by: Lars Fischer
         * input by: Ratheous
         * note 1: This reflects PHP 5.3/6.0+ behavior
         * note 2: Please be aware that this function expects to encode into
         *         UTF-8 encoded strings, as found on pages served as UTF-8
         ***********************************************************************
         */
        urlencode: function(str) {
            str = (str + '').toString();
            /**
             ***********************************************************************
             * Tilde should be allowed unescaped in future versions of PHP
             * (as reflected below), but if you want to reflect current
             * PHP behavior, you would need to add ".replace(/~/g, '%7E');" to the following.
             ***********************************************************************
             */
            return encodeURIComponent(str).replace(/!/g, '%21').replace(/'/g, '%27').replace(/\(/g, '%28').
                replace(/\)/g, '%29').replace(/\*/g, '%2A').replace(/%20/g, '+');
        },

        /**
         ***********************************************************************
         * From: http://phpjs.org/functions
         * original by: Kevin van Zonneveld (http://kevin.vanzonneveld.net)
         * improved by: Legaev Andrey
         * improved by: Michael White (http://getsprink.com)
         * improved by: Kevin van Zonneveld (http://kevin.vanzonneveld.net)
         * improved by: Brett Zamir (http://brett-zamir.me)
         * note 1: If the value is null, key and value is skipped in
         * http_build_query of PHP. But, phpjs is not.
         * depends on: urlencode
         ***********************************************************************
         */
        http_build_query: function(formdata, numeric_prefix, arg_separator) {
            var value, key, tmp = [], that = this;

            var _http_build_query_helper = function (key, val, arg_separator) {
                var k, tmp = [];
                if (val === true) {
                    val = "1";
                } else if (val === false) {
                    val = "0";
                }
                if (val != null) {
                    if(typeof val === "object") {
                        for (k in val) {
                            if (val[k] != null) {
                                tmp.push(_http_build_query_helper(key + "[" + k + "]", val[k], arg_separator));
                            }
                        }
                        return tmp.join(arg_separator);
                    } else if (typeof val !== "function") {
                        return that.urlencode(key) + "=" + that.urlencode(val);
                    } else {
                        throw new Error('There was an error processing for http_build_query().');
                    }
                } else {
                    return '';
                }
            };

            if (!arg_separator) {
                arg_separator = "&";
            }
            for (key in formdata) {
                value = formdata[key];
                if (numeric_prefix && !isNaN(key)) {
                    key = String(numeric_prefix) + key;
                }
                var query=_http_build_query_helper(key, value, arg_separator);
                if(query !== '') {
                    tmp.push(query);
                }
            }

            return tmp.join(arg_separator);
        },

        /**
         ***********************************************************************
         * From: http://phpjs.org/functions
         * original by: Kevin van Zonneveld (http://kevin.vanzonneveld.net)
         * improved by: Onno Marsman
         * bug fixed by: Daniel Esteban
         * improved by: Brett Zamir (http://brett-zamir.me)
         ***********************************************************************
         */
        strpos: function(haystack, needle, offset) {
            var i = (haystack + '').indexOf(needle, (offset || 0));
            return i === -1 ? false : i;
        },

        /**
         ***********************************************************************
         * Checks if the argument variable is empty,undefined, null, false,
         * number 0, empty string, string "0", objects without properties and
         * empty arrays
         * From: http://phpjs.org/functions
         * original by: Philippe Baumann
         * input by: Onno Marsman
         * bug fixed by: Kevin van Zonneveld (http://kevin.vanzonneveld.net)
         * input by: LH
         * improved by: Onno Marsman
         * improved by: Francesco
         * improved by: Marc Jansen
         * input by: Stoyan Kyosev (http://www.svest.org/)
         * improved by: Rafal Kukawski
         ***********************************************************************
         */
        empty: function(mixed_var) {
            var undef, key, i, len;
            var emptyValues = [undef, null, false, 0, "", "0"];

            for (i = 0, len = emptyValues.length; i < len; i++) {
                if (mixed_var === emptyValues[i]) {
                    return true;
                }
            }

            if (typeof mixed_var === "object") {
                for (key in mixed_var) {
                    // TODO: should we check for own properties only?
                    //if (mixed_var.hasOwnProperty(key)) {
                    return false;
                    //}
                }
                return true;
            }

            return false;
        },

        /**
         ***********************************************************************
         * From: http://phpjs.org/functions
         * original by: Cagri Ekin
         * improved by: Michael White (http://getsprink.com)
         * tweaked by: Jack
         * bug fixed by: Onno Marsman
         * reimplemented by: stag019
         * bug fixed by: Brett Zamir (http://brett-zamir.me)
         * bug fixed by: stag019
         * input by: Dreamer
         * bug fixed by: Brett Zamir (http://brett-zamir.me)
         * bug fixed by: MIO_KODUKI (http://mio-koduki.blogspot.com/)
         * input by: Zaide (http://zaidesthings.com/)
         * input by: David Pesta (http://davidpesta.com/)
         * input by: jeicquest
         * improved by: Brett Zamir (http://brett-zamir.me)
         * note 1: When no argument is specified, will put variables in global scope.
         *         When a particular argument has been passed, and the returned value
         *         is different parse_str of PHP. For example, a=b=c&d====c
         ***********************************************************************
         */
        parse_str: function(str, array) {
            var strArr = String(str).replace(/^&/, '').replace(/&$/, '').split('&'),
                sal = strArr.length,
                i, j, ct, p, lastObj, obj, lastIter, undef, chr, tmp, key, value,
                postLeftBracketPos, keys, keysLen,
                fixStr = function (str) {
                    return decodeURIComponent(str.replace(/\+/g, '%20'));
                };

            if (!array) {
                array = this.window;
            }

            for (i = 0; i < sal; i++) {
                tmp = strArr[i].split('=');
                key = fixStr(tmp[0]);
                value = (tmp.length < 2) ? '' : fixStr(tmp[1]);

                while (key.charAt(0) === ' ') {
                    key = key.slice(1);
                }
                if (key.indexOf('\x00') > -1) {
                    key = key.slice(0, key.indexOf('\x00'));
                }
                if (key && key.charAt(0) !== '[') {
                    keys = [];
                    postLeftBracketPos = 0;
                    for (j = 0; j < key.length; j++) {
                        if (key.charAt(j) === '[' && !postLeftBracketPos) {
                            postLeftBracketPos = j + 1;
                        }
                        else if (key.charAt(j) === ']') {
                            if (postLeftBracketPos) {
                                if (!keys.length) {
                                    keys.push(key.slice(0, postLeftBracketPos - 1));
                                }
                                keys.push(key.substr(postLeftBracketPos, j - postLeftBracketPos));
                                postLeftBracketPos = 0;
                                if (key.charAt(j + 1) !== '[') {
                                    break;
                                }
                            }
                        }
                    }
                    if (!keys.length) {
                        keys = [key];
                    }
                    for (j = 0; j < keys[0].length; j++) {
                        chr = keys[0].charAt(j);
                        if (chr === ' ' || chr === '.' || chr === '[') {
                            keys[0] = keys[0].substr(0, j) + '_' + keys[0].substr(j + 1);
                        }
                        if (chr === '[') {
                            break;
                        }
                    }

                    obj = array;
                    for (j = 0, keysLen = keys.length; j < keysLen; j++) {
                        key = keys[j].replace(/^['"]/, '').replace(/['"]$/, '');
                        lastIter = j !== keys.length - 1;
                        lastObj = obj;
                        if ((key !== '' && key !== ' ') || j === 0) {
                            if (obj[key] === undef) {
                                obj[key] = {};
                            }
                            obj = obj[key];
                        }
                        else { // To insert new dimension
                            ct = -1;
                            for (p in obj) {
                                if (obj.hasOwnProperty(p)) {
                                    if (+p > ct && p.match(/^\d+$/g)) {
                                        ct = +p;
                                    }
                                }
                            }
                            key = ct + 1;
                        }
                    }
                    lastObj[key] = value;
                }
            }
        },

        getUrlParam: function(param) {
            this.log('MonapiOauth:getUrlParam run!');
            var sPageURL = window.location.search.substring(1);
            var sURLVariables = sPageURL.split('&');
            for (var i = 0; i < sURLVariables.length; i++)
            {
                var sParameterName = sURLVariables[i].split('=');
                if (sParameterName[0] == param)
                {
                    return sParameterName[1];
                }
            }
            return false;
        },

        /**
         ***********************************************************************
         * Default for most applications.
         ***********************************************************************
         */
        access_token_name: 'access_token',

        /**
         ***********************************************************************
         * Version
         ***********************************************************************
         * @var string
         */
        version: '1.0.0',

        /**
         ***********************************************************************
         * List of query parameters that get automatically dropped when
         * rebuilding the current URL.
         ***********************************************************************
         * @var array
         */
        query_params: ['code','state'],

        /**
         ***********************************************************************
         * Maps aliases to Monapi domains.
         ***********************************************************************
         * @var array
         */
        domain_map: {
            graph: 'http://api.monapi.com/'
        },

        /**
         ***********************************************************************
         * Cookie prefix
         ***********************************************************************
         * @var string
         */
        cookie_name: 'monapi_cookie_name',

        /**
         ***********************************************************************
         * 1 Year
         ***********************************************************************
         * @var integer
         */
        cookie_expire: 31556926,

        /**
         ***********************************************************************
         * Supported keys for persistent data
         ***********************************************************************
         * @var array
         */
        sported_keys: [
            'state',
            'code',
            'access_token',
            'user_id'
        ],

        /**
         ***********************************************************************
         * The ID of the Monapi user, or 0 if the user is logged out.
         ***********************************************************************
         * @var integer
         */
        user: null,

        /**
         ***********************************************************************
         * A CSRF state variable to assist in the defense against CSRF attacks.
         ***********************************************************************
         * @var string
         */
        state: null,

        /**
         ***********************************************************************
         * The OAuth access token received in exchange for a valid authorization
         * code.  null means the access token has yet to be determined.
         ***********************************************************************
         * @var string
         */
        accessToken: null,


        initialize: function() {
            this.log('initialize run!');
            var state = this.getPersistentData('state', false);
            if (!state) {
                this.state = state;
            }
        },

        /**
         ***********************************************************************
         * Get the data for key, persisted by setPersistentData()
         ***********************************************************************
         * @param key string The key of the data to retrieve
         * @param default_value boolean The default value to return if key is not found
         * @return mixed
         */
        getPersistentData: function(key, default_value) {
            if(!this.in_array(key, this.sported_keys)) {
                this.log('Unsupported key passed to getPersistentData. => key:' + key);
                return default_value
            }

            var var_name = this.constructCookieVariableName(key);
            this.log('MonapiOauth:getPersistentData => key: ' + key + ' var_name: ' + var_name);
            return this.isSetCookie(var_name) ? $.cookie(var_name) : default_value;
        },

        log: function(message) {
            console.log(message);
        },


        /**
         ***********************************************************************
         * Stores the given (key, value) pair, so that future calls to
         * getPersistentData(key) return value. This call may be in another request.
         ***********************************************************************
         * @param key string
         * @param value array
         * @return void
         */
        setPersistentData: function(key, value) {
            if (!this.in_array(key, this.sported_keys)) {
                //throw new Error('Unsupported key passed to getPersistentData.');
                console.log('Unsupported key passed to setPersistentData. key: ' + key);
            } else {
                var var_name = this.constructCookieVariableName(key);
                this.log('MonapiOauth:setPersistentData => key :' + key + ' value : ' + value);
                $.cookie(var_name, value);
                this.log('Cookie : ' + $.cookie(var_name));
            }
        },

        /**
         ***********************************************************************
         * Constructs and returns the name of the session key.
         * @see setPersistentData()
         ***********************************************************************
         * @param key string The key for which the cookie variable name to construct.
         * @return string The name of the cookie key.
         */
        //@todo key
        constructCookieVariableName: function(key) {
            var parts = ['monapi', this.client_id, key];
            //return parts.join('_');
            return key;
        },

        /**
         * @param name string
         * @return boolean
         */
        isSetCookie: function(name) {
            var cookie = $.cookie(name);
            return cookie != null;
        },

        /**
         ***********************************************************************
         * Clear all data from the persistent storage
         ***********************************************************************
         * @var void
         */
        clearAllPersistentData: function() {
            this.log('MonapiOauth:clearAllPersistentData');
            for (var i = 0; i < this.sported_keys.length; ++i) {
                this.clearPersistentData(this.sported_keys[i]);
            }
        },

        /**
         ***********************************************************************
         * Clear the data with key from the persistent storage
         ***********************************************************************
         * @var void
         */
        clearPersistentData: function(key) {
            this.log('MonapiOauth:clearAllPersistentData => key => ' + key);
            if (!this.in_array(key, this.sported_keys)) {
                throw new Error('Unsupported key passed to clearPersistentData. key:' +  key);
            }
            var var_name = this.constructCookieVariableName(key);
            if(this.isSetCookie(var_name)) {
                $.removeCookie(var_name);
            }
        },

        /**
         ***********************************************************************
         * Configures the auth dialog url.
         ***********************************************************************
         */
        setupAuthUrl: function () {
            var url = this.auth_url + '?client_id=' + this.client_id
                + '&redirect_uri=' + this.redirect_url
                + '&response_type=token';
            if (this.scope) url += '&scope=' + this.scope;
            if (this.state) url += '&state=' + this.state;
            return url;
        },

        /**
         ***********************************************************************
         * Get the UID of the connected user, or 0
         * if the Monapi user is not connected.
         ***********************************************************************
         * @return integer the UID if available.
         */
        getUser: function() {
            this.log('MonapiOauth:getUser run!');
            if (this.user !== null) {
                this.log('MonapiOauth:getUser: we\'ve already determined this and cached the value. => user : ' + this.user);
                /**
                 * we've already determined this and cached the value.
                 */
                return this.user;
            }
            return this.user = this.getUserFromAvailableData();
        },

        /**
         ***********************************************************************
         * Determines the connected user by first examining any signed
         * requests, then considering an authorization code, and then
         * falling back to any persistent store storing the user.
         ***********************************************************************
         * @return integer The id of the connected Monapi user,
         *                 or 0 if no such user exists.
         */
        getUserFromAvailableData: function() {
            this.log('MonapiOauth:getUserFromAvailableData run!');

            var user = this.getPersistentData('user_id', 0);

            var persisted_access_token = this.getPersistentData('access_token', false);

            /**
             * use access_token to fetch user id if we have a user access_token, or if
             * the cached access token has changed.
             */
            var access_token = this.getAccessToken();

            this.log('MonapiOauth:getUserFromAvailableData access_token => ' + access_token);

            if (access_token && !(user && persisted_access_token == access_token)) {
                this.log('MonapiOauth:getUserFromAvailableData getUserFromAccessToken => ' + access_token);

                this.log('MonapiOauth:getUserFromAccessToken run');
                try{
                    var user_model  = new Me;
                    var self = this;
                    user_model.fetch({
                        async:false,
                        success: function (model, response) {
                            user = response.user_id;
                            if (user) {
                                self.setPersistentData('user_id', user);
                            } else {
                                self.clearAllPersistentData();
                                user = 0;
                            }
                        }
                    });
                } catch (err) {
                    this.log(err);
                    this.clearAllPersistentData();
                    this.log('MonapiOauth:getUserFromAccessToken catch return 0');
                    return 0;
                }
            }

            this.log('MonapiOauth:getUserFromAvailableData user => ' + user);
            return user;
        },

        /**
         ***********************************************************************
         * Determines the access token that should be used for API calls.
         * The first time this is called, this.accessToken is set equal
         * to either a valid user access token, or it's set to the application
         * access token if a valid user access token wasn't available.  Subsequent
         * calls return whatever the first call returned.
         ***********************************************************************
         * @return string The access token
         */
        getAccessToken: function() {
            this.log('MonapiOauth:getAccessToken run!');

            if (this.accessToken !== null) {

                this.log('we\'ve done this already and cached it. Just return accessToken => ' + this.accessToken);

                /**
                 * we've done this already and cached it.  Just return.
                 */
                return this.accessToken;
            }

            var user_access_token = this.getUserAccessToken();

            if (user_access_token) {
                this.setAccessToken(user_access_token);
            }
            return this.accessToken;
        },

        /**
         ***********************************************************************
         * Determines and returns the user access token, first using
         * the signed request if present, and then falling back on
         * the authorization code if present.  The intent is to
         * return a valid user access token, or false if one is determined
         * to not be available.
         ***********************************************************************
         * @return string A valid user access token, or false if one
         *                could not be determined.
         */
        getUserAccessToken: function() {
            this.log('MonapiOauth:getUserAccessToken run!');

            /**
             * as a fallback, just return whatever is in the persistent
             * store, knowing nothing explicit (signed request, authorization
             * code, etc.) was present to shadow it (or we saw a code in $_REQUEST,
             * but it's the same as what's in the persistent store)
             */
            return this.getPersistentData('access_token', false);
        },

        /**
         ***********************************************************************
         * Build the URL for given domain alias, path and parameters.
         ***********************************************************************
         * @param name string The name of the domain
         * @param path string Optional path (without a leading slash)
         * @param params array Optional query parameters
         * @return string The URL for the given parameters
         */
        //@todo override
        getUrl: function(name, path, params) {
            var url = this.domain_map[name];

            if (path != null) {
                if (path[0] === '/') {
                    path = path.substr(1);
                }
                url += path;
            }
            if (params) {
                url += '?' + this.http_build_query(params, null, '&');
            }
            this.log('MonapiOauth:getUrl => url : ' + url);
            return url;
        },

        /**
         ***********************************************************************
         * Returns the Current URL, stripping it of known Monapi parameters that
         * should not persist.
         ***********************************************************************
         * @return string The current URL
         */
        getCurrentUrl: function() {
            return document.URL;
        },

        /**
         ***********************************************************************
         * Sets the access token for api calls.  Use this if you get
         * your access token by other means and just want the SDK
         * to use it.
         ***********************************************************************
         * @param access_token string an access token.
         */
        setAccessToken: function(access_token) {
            this.accessToken = access_token;
            return this;
        },

        /**
         ***********************************************************************
         * Open the OAuth dialog and wait for a redirect.
         ***********************************************************************
         */
        auth: function () {
            if (!this.access_token_name)
                throw new Error('No access token name given.');
            if (!this.auth_url)
                throw new Error('No auth url given.');
            if (!this.redirect_url)
                throw new Error('No redirect url given.');
            //this.ping();
            this.dialog = window.open(this.setupAuthUrl(),'opener','location=0,status=0,width=500,height=480');
        },

        ping:function() {
            var url = this.auth_url + '?client_id=' + this.client_id
                + '&redirect_uri=' + this.redirect_url
                + '&response_type=token';
            if (this.scope) url += '&scope=' + this.scope;
            if (this.state) url += '&state=' + this.state;

            $.get( url, function( data ) {
                alert( "Load was performed." );
            });

        },

        /**
         ***********************************************************************
         * Called on redirection inside the OAuth dialog window. This indicates,
         * that the dialog auth process has finished. It has to be checked, if
         * the auth was successful or not.
         ***********************************************************************
         */
        onRedirect: function (hash) {
            var params = parseHash(hash);
            if (this.authSuccess(params)) {
                this.onSuccess(params);
            } else {
                this.onError(params);
            }
        },

        /**
         ***********************************************************************
         * Detect if we have a successful auth.
         ***********************************************************************
         */
        authSuccess: function (params) {
            return params[this.access_token_name];
        },

        /**
         ***********************************************************************
         * These following methods have to be implemented by the OAuth application.
         ***********************************************************************
         */
        onError: function (params) {
            console.log(1);
            console.log('error');
            this.clearAllPersistentData();
        },

        onSuccess: function (params) {
            this.user = null;
            this.clearAllPersistentData();
            this.log('MonapiOauth:onSuccess: access_token = ' + params['access_token']);
            this.setPersistentData('access_token', params['access_token']);
            this.getUser();
            //window.location.replace(this.getCurrentUrl());
            window.location = this.getCurrentUrl();
        }
    });

    /*
     * Me model
     */
    var Me = Backbone.Model.extend({
        url: 'http://api.note.stage.monapi.com/me',
        defaults: {
            username: null,
            email: null,
            group_id: null,
            group_name: null,
            permissions: []
        }
    });



})(this);
