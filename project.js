(function(){

    // Initial Setup
    // -------------

    // Save a reference to the global object (`window` in the browser, `exports`
    // on the server).
    var root = this;


    // The top-level namespace. All public Backbone classes and modules will
    // be attached to this. Exported for both the browser and the server.
    var Monapi;

    if (typeof exports !== 'undefined') {
        Monapi = exports;
    } else {
        Monapi = root.Monapi = {};
    }

    // Current version of the library. Keep in sync with `package.json`.
    Monapi.VERSION = '1.0.0';

    Monapi.Oauth = Backbone.OAuth;

    Monapi.UserCollection = Backbone.Model.extend({
        idAttribute: "user_id",
        setName:function(name) {
            this.set({name:name});
        },
        getName:function() {
            return this.get('name');
        }
    });

    Monapi.UserFilter = {
        user_id:null,
        name:null,
        setName:function(name) {
            this.name = name;
        },
        getName:function() {
            return this.name
        },
        render:function() {

        }
    };

    Monapi.Note = Backbone.Model.extend({
        idAttribute: "note_id",
        setName:function(name) {
            this.set({name:name});
        },
        getName:function() {
            return this.get('name');
        },
        userCollection:function(filter) {
            var collection = new Monapi.UserCollection();
            if(filter === null || filter === undefined) {
                filter= {};
            } else {
                filter = {data:$.param(filter)};
            }
            return collection.fetch(filter)

        }
    });

    Monapi.UserCollection = Backbone.Collection.extend({
        model: Monapi.User,
        url:'http://api.note.stage.monapi.com/organisation'
    });


}).call(this);

(function (window, Monapi) {

    Backbone.OAuth.config = {
        auth_url: 'http://api.note.stage.monapi.com/dialog/oauth',
        redirect_url: 'http://' + window.location.host + '/callback.html',
        scope : '',
        state : 1,
        client_id: '3'
    };

    var Project = new Monapi.Oauth(Backbone.OAuth.config);

    if(!Project.getUser()) {
        Project.auth();
    }

    var Note =   new Monapi.Note();
    Note.setName('zeki');

    var userFilter = Monapi.UserFilter;
    userFilter.setName('zeki');

    Note.userCollection({
        user_id:2,
        fields:[
            'organisation_id',
            'user_id',
            'default',
            {
                organisation:{
                    fields:[
                        'organisation_id',
                        'name'
                    ]
                }
            }
        ]
    });

    console.log(Note.getName());

})(this,Monapi);


