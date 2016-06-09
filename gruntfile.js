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
					"src": [
						"assets/admin/js/secupress-common.js",
						"assets/admin/js/secupress-modules.js",
						"assets/admin/js/secupress-notices.js",
						"assets/admin/js/secupress-scanner.js",
						"assets/admin/js/secupress-wordpress.js"
					]
				}
			}
		},
		"uglify": {
			"all": {
				"files": [
					{
						"src":  "assets/admin/js/secupress-common.js",
						"dest": "assets/admin/js/secupress-common.min.js"
					},
					{
						"src":  "assets/admin/js/secupress-modules.js",
						"dest": "assets/admin/js/secupress-modules.min.js"
					},
					{
						"src":  "assets/admin/js/secupress-notices.js",
						"dest": "assets/admin/js/secupress-notices.min.js"
					},
					{
						"src":  "assets/admin/js/secupress-scanner.js",
						"dest": "assets/admin/js/secupress-scanner.min.js"
					},
					{
						"src":  "assets/admin/js/secupress-wordpress.js",
						"dest": "assets/admin/js/secupress-wordpress.min.js"
					}
				]
			}
		},
		"cssmin": {
			"all": {
				"files": [
					{
						"src":  "assets/admin/css/secupress-action-page.css",
						"dest": "assets/admin/css/secupress-action-page.min.css"
					},
					{
						"src":  "assets/admin/css/secupress-common.css",
						"dest": "assets/admin/css/secupress-common.min.css"
					},
					{
						"src":  "assets/admin/css/secupress-logs.css",
						"dest": "assets/admin/css/secupress-logs.min.css"
					},
					{
						"src":  "assets/admin/css/secupress-modules.css",
						"dest": "assets/admin/css/secupress-modules.min.css"
					},
					{
						"src":  "assets/admin/css/secupress-notices.css",
						"dest": "assets/admin/css/secupress-notices.min.css"
					},
					{
						"src":  "assets/admin/css/secupress-scanner.css",
						"dest": "assets/admin/css/secupress-scanner.min.css"
					},
					{
						"src":  "assets/admin/css/secupress-settings.css",
						"dest": "assets/admin/css/secupress-settings.min.css"
					},
					{
						"src":  "assets/admin/css/secupress-wordpress-3.7.css",
						"dest": "assets/admin/css/secupress-wordpress-3.7.min.css"
					},
					{
						"src":  "assets/admin/css/secupress-wordpress.css",
						"dest": "assets/admin/css/secupress-wordpress.min.css"
					},
					{
						"src":  "assets/admin/css/sweetalert2.css",
						"dest": "assets/admin/css/sweetalert2.min.css"
					}
				]
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
	grunt.loadNpmTasks( "grunt-contrib-uglify" );
	grunt.loadNpmTasks( "grunt-contrib-cssmin" );
	grunt.loadNpmTasks( "grunt-newer" );
	grunt.loadNpmTasks( "grunt-dev-update" );

	grunt.registerTask( "jsh", [ "jshint" ] );
	grunt.registerTask( "minify", [ "newer:jshint", "newer:uglify", "newer:cssmin" ] );
};
