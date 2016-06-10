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
			"options": {
				"shorthandCompacting": false,
				"roundingPrecision": -1
			},
			"target": {
				"files": [{
					"expand": true,
					"cwd": "assets/admin/css",
					"src": ["*.css", "!*.min.css"],
					"dest": "assets/admin/css",
					"ext": ".min.css"
				}]
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
	grunt.registerTask( "css", [ "cssmin" ] );
	grunt.registerTask( "minify", [ "newer:jshint", "newer:uglify", "newer:cssmin" ] );
};
