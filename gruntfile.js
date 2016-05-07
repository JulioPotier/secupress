module.exports = function( grunt ) {
	grunt.initConfig( {
		"jshint": {
			"options": {
				"reporter": require( "jshint-stylish" ),
				"jshintrc": ".jshintrc",
				"force": true
			},
			"all": {
				"files": {
					"src": [ "assets/admin/js/secupress-common.js", "assets/admin/js/secupress-modules.js", "assets/admin/js/secupress-notices.js", "assets/admin/js/secupress-scanner.js", "assets/admin/js/secupress-scanner.js", "assets/admin/js/secupress-wordpress.js" ]
				}
			}
		},
		"devUpdate": {
			"check": {
				"options": {
					"reportUpdated": true
				}
			},
			"update": {
				"options": {
					"updateType": "force",
					"reportUpdated": true,
					"semver": false
				}
			}
		}
	} );

	grunt.loadNpmTasks( "grunt-contrib-jshint" );
	grunt.loadNpmTasks( "grunt-dev-update" );

	grunt.registerTask( "jsh", [ "jshint" ] );
};
