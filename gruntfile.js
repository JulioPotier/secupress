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
		"postcss": {
			"options": {
				"processors": [
					require('autoprefixer')({
						"browsers": 'last 3 versions'
					}), // add vendor prefixes
					require('cssnano')() // minify the result
				]
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
	grunt.loadNpmTasks( "grunt-postcss" );
	grunt.loadNpmTasks( "grunt-newer" );
	grunt.loadNpmTasks( "grunt-dev-update" );

	grunt.registerTask( "jsh", [ "jshint" ] );
	grunt.registerTask( "css", [ "postcss" ] );
	grunt.registerTask( "minify", [ "newer:jshint", "newer:uglify", "newer:postcss" ] );
};
