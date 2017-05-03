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
						"assets/admin/js/secupress-wordpress.js",
						"inc/modules/users-login/plugins/inc/js/captcha.js"
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
					},
					{
						"src":  "inc/modules/users-login/plugins/inc/js/captcha.js",
						"dest": "inc/modules/users-login/plugins/inc/js/captcha.min.js"
					}
				]
			}
		},
		"postcss": {
			"options": {
				"processors": [
					require( 'autoprefixer' )( {
						"browsers": 'last 3 versions'
					} ) // add vendor prefixes
				]
			},
			"target": {
				"files": [ {
					"expand": true,
					"cwd":    "assets/admin/css",
					"src":    [ "*.css", "!*.min.css" ],
					"dest":   "assets/admin/css",
					"ext":    ".min.css"
				} ]
			}
		},
		"cssmin": {
			"options": {
				"shorthandCompacting": false,
				"roundingPrecision": -1
			},
			"target": {
				"files": [ {
					"expand": true,
					"cwd":    "assets/admin/css",
					"src":    [ "*.min.css" ],
					"dest":   "assets/admin/css",
					"ext":    ".min.css"
				} ]
			}
		},
		'copy': {
			'no-longer-in-directory': {
				'files': [
					{
						'expand': true,
						'nonull': true,
						'cwd': '../no-longer-in-directory',
						'src':  '*-plugin-list.txt',
						'dest': 'inc/data/',
						'ext': '.data'
					}
				]
			}
		}
	} );

	// Allow local configuration, for file paths for example.
	if ( grunt.file.exists( 'gruntlocalconf.json' ) ) {
		grunt.config.merge( grunt.file.readJSON( 'gruntlocalconf.json' ) );
	}

	grunt.loadNpmTasks( "grunt-contrib-jshint" );
	grunt.loadNpmTasks( "grunt-contrib-uglify" );
	grunt.loadNpmTasks( "grunt-contrib-cssmin" );
	grunt.loadNpmTasks( "grunt-postcss" );
	grunt.loadNpmTasks( "grunt-newer" );
	grunt.loadNpmTasks( "grunt-dev-update" );
	grunt.loadNpmTasks( "grunt-contrib-copy" );

	grunt.registerTask( "css", [ "postcss", "cssmin" ] );
	grunt.registerTask( "js", [ "newer:jshint", "newer:uglify" ] );
	grunt.registerTask( "jsh", [ "jshint" ] );
	grunt.registerTask( "minify", [ "jshint", "uglify", "postcss", "cssmin" ] );
	grunt.registerTask( "minify-force", [ "minify" ] );
};
