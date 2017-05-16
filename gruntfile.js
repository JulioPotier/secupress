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
		},
		'http': {
			'10k-most-common': {
				'options': {
					'url':     'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/10k_most_common.txt',
					'timeout': 10000
				},
				'dest': 'inc/data/10kmostcommon.data'
			},
			'no-longer-in-directory': {
				'options': {
					'url':     'https://plugins.svn.wordpress.org/no-longer-in-directory/trunk/no-longer-in-directory-plugin-list.txt',
					'timeout': 10000
				},
				'dest': 'inc/data/no-longer-in-directory-plugin-list.data'
			},
			'not-updated-in-over-two-years': {
				'options': {
					'url':     'https://plugins.svn.wordpress.org/no-longer-in-directory/trunk/not-updated-in-over-two-years-plugin-list.txt',
					'timeout': 10000
				},
				'dest': 'inc/data/not-updated-in-over-two-years-plugin-list.data'
			},
			'spam-blacklist': {
				'options': {
					'url':     'https://raw.githubusercontent.com/splorp/wordpress-comment-blacklist/master/blacklist.txt',
					'timeout': 10000
				},
				'dest': 'inc/data/spam-blacklist.data'
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
	grunt.loadNpmTasks( "grunt-http" );

	grunt.registerTask( "css", [ "postcss", "cssmin" ] );
	grunt.registerTask( "js", [ "newer:jshint", "newer:uglify" ] );
	grunt.registerTask( "jsh", [ "jshint" ] );
	grunt.registerTask( "minify", [ "jshint", "uglify", "postcss", "cssmin" ] );
	grunt.registerTask( "minify-force", [ "minify" ] );
	grunt.registerTask( "data", [ "http:10k-most-common", "http:no-longer-in-directory", "http:not-updated-in-over-two-years", "http:spam-blacklist" ] );
};
