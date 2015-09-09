<?php
//// _n() !!
defined( 'ABSPATH' ) or die( 'Cheatin\' uh?' );

abstract class SecuPress_Scanners_Functions {

	static public $remote_args = array( 'redirection' => 0 );
	// internal functions
	static public function set_status( &$data, $status ) {
		if ( ( ! isset( $data['status'] ) || 'Good' == $data['status'] ) ||
			( 'Warning' == $data['status'] && 'Bad' == $status )
		){
			$data['status'] = $status;
		}
	}

	static public function set_message( &$data, $message ) {
		if ( '' == $message ) {
			return;
		}
		if ( ! isset( $data['message'] ) ) {
			$data['message'] = '';
		}
		$data['message'] .= '<li>' . $message . '</li>';
	}

	static public function remove_comments( $string ) {
		$string = preg_replace( "%(#|(//)).*%", '', $string );
		$string = preg_replace( "%/\*(?:(?!\*/).)*\*/%s", '', $string );
		return $string;
	}

	function dictionary_attack( $password ) {
		$dictionary = file( SECUPRESS_INC_URL . 'data/10kmostcommon.txt', FILE_IGNORE_NEW_LINES);
		return in_array( $password, $dictionary );
	}

	/* Scanners functions */

	/**
	 * @return array
	 */
	static public function bad_old_files() {
		require_once( ABSPATH . 'wp-admin/includes/update-core.php' );
		$return = array();
		self::set_status( $return, 'Good' );
		foreach ( $GLOBALS['_old_files'] as $file ) {
			if ( @file_exists( ABSPATH . $file ) ) {
				self::set_status( $return, 'Bad' );
				self::set_message( $return, __( 'Your installation contains old files.', 'secupress' ) );
				break;
			}
		}

		return $return;
	}

	/**
	 * @return array
	 */
	static public function bad_config_files() {
		$return = array();
		self::set_status( $return, 'Good' );

		// multiple *wp-config*.*
		$check = array_flip( array_map( 'basename', (array) glob( ABSPATH . '*wp-config*.*' ) ) );
		unset( $check['wp-config.php'], $check['wp-config-sample.php'] );
		if ( count( $check ) ) {
			self::set_status( $return, 'Bad' );
			self::set_message( $return, sprintf( __( 'Your installation shouldn\'t contain these old or backed up config files: <code>%s</code>', 'secupress' ), implode( '</code>, <code>', array_flip( $check ) ) ) );
		}

		return $return;
	}

	static public function bad_url_access() {
		$return = array();
		self::set_status( $return, 'Good' );
		remove_all_filters( 'site_url' ); // avoid plugin's hooks of course
		remove_all_filters( 'admin_url' ); // avoid plugin's hooks of course
		$urls = array( 	admin_url( 'install.php' ),
			//admin_url( 'upgrade.php' ),
			site_url( 'wp-login.php', 'login' ),
			home_url( 'php.ini' ),
			admin_url( 'menu-header.php' ),
			admin_url( 'includes/menu.php' ),
		);
		foreach ( $urls as $url ) {
			$response = wp_remote_get( $url, self::$remote_args );
			if ( ! is_wp_error( $response ) ) {
				if ( 200 === wp_remote_retrieve_response_code( $response ) ) {
					self::set_status( $return, 'Bad' );
					self::set_message( $return, sprintf( __( '<code>%s</code> shouldn\'t be accessible by anyone.', 'secupress' ), $url ) );
				}
			} else {
				self::set_status( $return, 'Warning' );
				self::set_message( $return, sprintf( __( 'Unable to determine status of <code>%s</code>.', 'secupress' ), $url ) );
			}
		}

		return $return;
	}

	static public function php_ini_check() {
		$return = array();

		$ini_values = array(    'register_globals' => false, 'display_errors' => false, 'expose_php' => false,
			'allow_url_include' => false, 'safe_mode' => false, 'open_basedir' => '!empty',
			'log_errors' => 1, 'error_log' => '!empty',
			'post_max_size' => '<64M', 'upload_max_filezize' => '<64M', 'memory_limit' => '<1024M',
			'disable_functions' => '!empty', 'auto_append_file' => false, 'auto_prepend_file' => false
		);
		foreach( $ini_values as $value => $compare ) {
			$check = ini_get( $value );
			switch( $compare ) {
				case '!empty':
					if ( '' == ( $check ) ) {
						self::set_status( $return, 'Bad' );
						self::set_message( $return, sprintf( __( '<code>%1$s</code> shouldn\'t be empty.', 'secupress' ), $value ) );
					}
					break;
				case 1:
					if ( ! $check ) {
						self::set_status( $return, 'Bad' );
						self::set_message( $return, sprintf( __( '<code>%1$s</code> should be set on %2$s.', 'secupress' ), $value, '<code>On</code>' ) );
					}
					break;
				case false:
					if ( $check ) {
						self::set_status( $return, 'Bad' );
						self::set_message( $return, sprintf( __( '<code>%1$s</code> should be set on %2$s.', 'secupress' ), $value, '<code>Off</code>' ) );
					}
					break;
				default:
					if ( '<' === $compare[0] ) {
						$int = substr( $compare, 1, strlen( $compare ) - 2 );
						$check = substr( $check, 0, strlen( $check ) - 2 ) <= $int;
						if ( ! $check ) {
							self::set_status( $return, 'Bad' );
							self::set_message( $return, sprintf( __( '<code>%1$s</code> should be set on %2$s.', 'secupress' ), $value, str_replace( array( '<', 'M' ), array( '&lt; <code>', 'M</code>' ), $compare ) ) );
						}
					}
					break;
			}
		}

		return $return;
	}

	static function subscription_check() {
		$return = array();
		self::set_status( $return, 'Good' );


		// open subscription
		$check   = get_option( 'users_can_register' );
		if ( $check ) {
			// default role
			$check   = get_option( 'default_role' );
			if ( 'subscriber' != $check ) {
				self::set_status( $return,  'Bad' );
				self::set_message( $return, sprintf( __( 'The default role in your installation is <code>%s</code> and it should be <code>subscriber</code> or registrations should be <b>closed</b>.', 'secupress' ), $check ) );
			}
			$user_login = 'secupress_' . time();
			$post_data = array( 'body' => array( 'user_login' => $user_login, 'user_email' => 'secupress_no_mail@fakemail.' . time() ) );
			$response = wp_remote_post( wp_registration_url(), $post_data );
			$user_exists = username_exists( $user_login );
			if ( ! is_wp_error( $response ) ) {
				if ( $user_exists || 'failed' == get_transient( 'secupress_registration_test' ) ) {
					self::set_status($return, 'Bad');
					self::set_message($return, __( 'The registration page is <b>not protected</b> from bots.', 'secupress' ) );
				}
			} else {
				self::set_status( $return, 'Warning' );
				self::set_message( $return, __( 'Unable to determine status of your homepage.', 'secupress' ) );
			}
			delete_transient( 'secupress_registration_test' );
		}

		return $return;

	}

	static public function admin_user_check() {
		$return = array();
		self::set_status( $return, 'Good' );

		// admin user
		$check = username_exists( 'admin' );
		// should not be administrator
		if ( isset( $check->ID ) && user_can( $check, 'administrator' ) ) {
			self::set_status( $return, 'Bad' );
			self::set_message( $return, __( 'The <i>admin</i> account role shouldn\'t be an <b>administrator</b>.', 'secupress' ) );
		}

		// ID should be > 25 to avoid simple SQLi
		if ( isset( $check->ID ) && ( $check->ID < 25 ) ) {
			self::set_status( $return, 'Bad' );
			self::set_message( $return, __( 'The <i>admin</i> account <code>ID</code> should be greater than <b>50</b>.', 'secupress' ) );
		}

		// "admin' user should exists to avoid the creation of this user
		if ( get_option( 'users_can_register' ) && ! isset( $check->ID ) ) {
			self::set_status( $return, 'Bad' );
			self::set_message( $return, __( 'The <i>admin</i> account should exists (with no role) to avoid someone to register it.', 'secupress' ) );
		}

		return $return;
	}

	static function admin_as_author(){
		$return = array();
		self::set_status( $return, 'Good' );

		// are the administrators authors too? (i hope not)
		$ids = get_posts( array( 'fields' => 'ids', 'author__in' => get_users( array( 'fields' => 'ids', 'role' => 'administrator' ) ) ) );
		if ( count( $ids ) ) {
			self::set_status( $return, 'Bad' );
			self::set_message( $return, sprintf( __( '<b>%d</b> posts have an <b>administrator</b> as an author.', 'secupress' ), count( $ids ) ) );
		}

		return $return;
	}

	static function too_many_admins(){
		$return = array();
		self::set_status( $return, 'Good' );

		// are the administrators authors too? (i hope not)
		$ids = get_users( array( 'fields' => 'ids', 'role' => 'administrator' ) );
		if ( count( $ids ) > 3 ) {
			self::set_status( $return, 'Bad' );
			self::set_message( $return, sprintf( __( '<b>%d administrators</b> found on this site.', 'secupress' ), count( $ids ) ) );
		}

		return $return;
	}


	static function easy_login(){
		$return = array();
		self::set_status( $return, 'Good' );

		// check easy login
		$temp_login = uniqid( 'secupress' );
		$temp_pass = wp_generate_password( 64 );
		$temp_id = wp_insert_user( array( 	'user_login' => $temp_login,
				'user_pass' => $temp_pass,
				'user_email' => 'secupress_no_mail@fakemail.' . time(),
				'role' => 'secupress_no_role_' . time(),
			)
		);
		if ( ! is_wp_error( $temp_id ) ) {
		$check = wp_authenticate( $temp_login, $temp_pass );
		wp_delete_user( $temp_id );
		if( is_a( $check, 'WP_User' ) ) {
			self::set_status( $return, 'Bad' );
			self::set_message( $return, __( 'Your login system is <b>not strong enought</b>, you need a <b>two authentication system</b>.', 'secupress' ) );
	}
		} else {
			self::set_status( $return, 'Warning' );
			self::set_message( $return, __( 'Unable to create a user to test the login authentication system.', 'secupress' ) );
		}

		return $return;
	}

	static function bad_usernames() {
		$return = array();
		self::set_status( $return, 'Good' );

		// blacklisted names
		$names = array( //// mettre ça dans une option
			'a', 'about', 'access', 'account', 'accounts', 'ad', 'address', 'adm', 'admin', 'administration', 'adult', 'advertising', 'affiliate', 'affiliates', 'ajax', 'analytics', 'android', 'anon', 'anonymous', 'api', 'app', 'apps', 'archive', 'atom', 'auth', 'authentication', 'avatar',
			'b', 'backup', 'banner', 'banners', 'bin', 'billing', 'blog', 'blogs', 'board', 'bot', 'bots', 'business',
			'c', 'chat', 'cache', 'cadastro', 'calendar', 'campaign', 'careers', 'cdn', 'cgi', 'client', 'cliente', 'code', 'comercial', 'compare', 'config', 'connect', 'contact', 'contest', 'create', 'code', 'compras', 'css',
			'd', 'dashboard', 'data', 'db', 'design', 'delete', 'demo', 'design', 'designer', 'dev', 'devel', 'dir', 'directory', 'doc', 'documentation', 'docs', 'domain', 'download', 'downloads',
			'e', 'edit', 'editor', 'email', 'ecommerce',
			'f', 'forum', 'forums', 'faq', 'favorite', 'feed', 'feedback', 'flog', 'follow', 'file', 'files', 'free', 'ftp',
			'g', 'gadget', 'gadgets', 'games', 'guest', 'group', 'groups',
			'h', 'help', 'home', 'homepage', 'host', 'hosting', 'hostname', 'htm', 'html', 'http', 'httpd', 'https', 'hpg',
			'i', 'info', 'information', 'image', 'img', 'images', 'imap', 'index', 'invite', 'intranet', 'indice', 'ipad', 'iphone', 'irc',
			'j', 'java', 'javascript', 'job', 'jobs', 'js',
			'k', 'knowledgebase',
			'l', 'log', 'login', 'logs', 'logout', 'list', 'lists',
			'm', 'mail', 'mail1', 'mail2', 'mail3', 'mail4', 'mail5', 'mailer', 'mailing', 'mx', 'manager', 'marketing', 'master', 'me', 'media', 'message', 'microblog', 'microblogs', 'mine', 'mp3', 'msg', 'msn', 'mysql', 'messenger', 'mob', 'mobile', 'movie', 'movies', 'music', 'musicas', 'my',
			'n', 'name', 'named', 'net', 'network', 'new', 'news', 'newsletter', 'nick', 'nickname', 'notes', 'noticias', 'ns', 'ns1', 'ns2', 'ns3', 'ns4', 'ns5', 'ns6', 'ns7', 'ns8', 'ns9',
			'o', 'old', 'online', 'operator', 'order', 'orders',
			'p', 'page', 'pager', 'pages', 'panel', 'password', 'perl', 'pic', 'pics', 'photo', 'photos', 'photoalbum', 'php', 'plugin', 'plugins', 'pop', 'pop3', 'post', 'postmaster', 'postfix', 'posts', 'private', 'profile', 'project', 'projects', 'promo', 'pub', 'public', 'python',
			'q',
			'r', 'random', 'register', 'registration', 'root', 'ruby', 'rss',
			's', 'sale', 'sales', 'sample', 'samples', 'script', 'scripts', 'secure', 'send', 'service', 's'.'e'.'x', 'shop', 'sql', 'signup', 'signin', 'search', 'security', 'settings', 'setting', 'setup', 'site', 'sites', 'sitemap', 'smtp', 'soporte', 'ssh', 'stage', 'staging', 'start', 'subscribe', 'subdomain', 'suporte', 'support', 'stat', 'static', 'stats', 'status', 'store', 'stores', 'system',
			't', 'tablet', 'tablets', 'tech', 'telnet', 'test', 'test1', 'test2', 'test3', 'teste', 'tests', 'theme', 'themes', 'tmp', 'todo', 'task', 'tasks', 'tools', 'tv', 'talk',
			'u', 'update', 'upload', 'url', 'user', 'username', 'usuario', 'usage',
			'v', 'vendas', 'video', 'videos', 'visitor',
			'w', 'win', 'ww', 'www', 'www1', 'www2', 'www3', 'www4', 'www5', 'www6', 'www7', 'www9', 'www9', 'wwww', 'wws', 'wwws', 'web', 'webmail', 'website', 'websites', 'webmaster', 'workshop',
			'x', 'xxx', 'xpg',
			'y', 'you',
			'z'
		);

		global $wpdb;
		$req = 'SELECT ID from ' . $wpdb->users . ' WHERE user_login IN ( "' . implode( '", "', $names ) . '" )';
		$ids = $wpdb->get_col( $req );
		if ( count( $ids ) ) {
			self::set_status( $return, 'Bad' );
			self::set_message( $return, sprintf( __( '<b>%d</b> user\'s login contains forbidden names.', 'secupress' ), count( $ids ) ) );
		}

		// who got the same nickname and login
		$req = "SELECT ID FROM $wpdb->users u, $wpdb->usermeta um WHERE u.user_login=u.display_name OR (um.user_id=u.ID AND um.meta_key='nickname' AND um.meta_value=u.user_login ) GROUP BY ID";
		$ids = $wpdb->get_col( $req );
		if ( count( $ids ) ) {
			self::set_status( $return, 'Bad' );
			self::set_message( $return, sprintf( __( '<b>%d</b> user\'s login are similar to their display name.', 'secupress' ), count( $ids ) ) );
		}

		return $return;
	}

	static public function ver_check() {
		$return = array();
		self::set_status( $return, 'Good' );

		// Core
		if ( ! function_exists( 'get_preferred_from_update_core' ) ) {
			require_once( ABSPATH . 'wp-admin/includes/update.php' );
		}

		wp_version_check();
		$latest_core_update = get_preferred_from_update_core();

		// Plugins
		$current = get_site_transient( 'update_plugins' );

		if ( ! is_object( $current ) ) {
			$current = new stdClass;
		}

		$current = get_site_transient( 'update_plugins' );

		$plugin_updates = array();
		if ( isset( $current->response ) && is_array( $current->response ) ) {
			$plugin_updates = wp_list_pluck( array_intersect_key( get_plugins(), array_flip( array_keys( $current->response ) ) ), 'Name' );
		}

		// Themes
		$current = get_site_transient( 'update_themes' );

		if ( ! is_object( $current ) ) {
			$current = new stdClass;
		}

		$current = get_site_transient( 'update_themes' );

		$theme_updates = array();
		if ( isset( $current->response ) && is_array( $current->response ) ) {
			$theme_updates = wp_list_pluck( array_map( 'wp_get_theme', array_keys( $current->response ) ), 'Name' );
		}

		if ( isset( $latest_core_update->response ) && ( $latest_core_update->response == 'upgrade' ) ||
			$plugin_updates || $theme_updates
		) {
			self::set_status( $return, 'Bad' );
			if ( isset( $latest_core_update->response ) && ( 'upgrade' == $latest_core_update->response ) ) {
				self::set_message( $return, __( 'WordPress <b>core</b> is not up to date.', 'secupress' ) );
			}
			if ( count( $plugin_updates ) ) {
				self::set_message( $return, sprintf( _n( '<b>%1$d</b> plugin isn\'t up to date: <code>%2$s</code>.', '<b>%1$d</b> plugins aren\'t up to date: <code>%2$s</code>.', count( $plugin_updates ), 'secupress' ), count( $plugin_updates ), implode( '</code>, <code>', $plugin_updates ) ) );
			}
			if ( count( $theme_updates ) ) {
				self::set_message( $return, sprintf( _n( '<b>%1$d</b> theme isn\'t up to date: <code>%2$s</code>', '<b>%1$d</b> themes aren\'t up to date: <code>%2$s</code>', count( $theme_updates ), 'secupress' ), count( $theme_updates ), implode( '</code>, <code>', $theme_updates ) ) );
			}
		}

		// PHP version
		$min_php_version = '5.4.39'; // http://php.net/supported-versions.php
		if ( version_compare( PHP_VERSION, $min_php_version ) < 0 ) {
			self::set_status( $return, 'Bad' );
			self::set_message( $return, sprintf( __( 'Your server is running on <code>PHP v%1$s</code>, it\'s an outdated version, use <code>v%2$s</code> at least.', 'secupress' ), PHP_VERSION, $min_php_version ) );
		}


		return $return;
	}

	static public function bad_old_plugins() {

		$return = array();
		self::set_status( $return, 'Good' );

		// plugins no longer in directory
		// http://plugins.svn.wordpress.org/no-longer-in-directory/trunk/
		$plugin_list = SECUPRESS_INC_PATH . 'data/no-longer-in-directory-plugin-list.txt';
		if ( is_readable( $plugin_list ) ) {
			$no_longer_in_directory_plugin_list = array_flip( array_map( 'chop', file( $plugin_list ) ) );
			$all_plugins = array_combine( array_map( 'dirname', array_keys( get_plugins() ) ), get_plugins() );
			$check = array_intersect_key( $all_plugins, $no_longer_in_directory_plugin_list );
			if ( count( $check ) ) {
				$number = _n( '<b>%d</b> plugin is <b>no longer</b> in the WordPress directory: <code>%s</code>', '<b>%d</b> plugins are <b>no longer</b> in the WordPress directory: <code>%s</code>', count( $count ), 'secupress' );
				self::set_status( $return, 'Bad' );
				self::set_message( $return, sprintf( $number, count( $check ), implode( '</code>, <code>', wp_list_pluck( $check, 'Name' ) ) ) );
			}
		} else {
			self::set_status( $return, 'Warning' );
			self::set_message( $return, sprintf( __( 'Error, could not read <code>%s</code>.', 'secupress' ), $plugin_list ) );
		}

		// plugins not updated in over 2 years
		// http://plugins.svn.wordpress.org/no-longer-in-directory/trunk/
		$plugin_list = SECUPRESS_INC_PATH . 'data/not-updated-in-over-two-years-plugin-list.txt';
		if ( is_readable( $plugin_list ) ) {
			$no_longer_in_directory_plugin_list = array_flip( array_map( 'chop', file( $plugin_list ) ) );
			$all_plugins = array_combine( array_map( 'dirname', array_keys( get_plugins() ) ), get_plugins() );
			$check = array_intersect_key( $all_plugins, $no_longer_in_directory_plugin_list );
			if ( count( $check ) ) {
				$number = _n( '<b>%d</b> plugin haven\'t been updated <b>since 2 years</b> at least: <code>%s</code>', '<b>%d</b> plugins haven\'t been updated <b>since 2 years</b> at least: <code>%s</code>', count( $count ), 'secupress' );
				self::set_status($return, 'Bad' );
				self::set_message($return, sprintf( $number, count( $check ), implode('</code>, <code>', wp_list_pluck( $check, 'Name' ) ) ) );
			}
		} else {
			self::set_status($return, 'Warning' );
			self::set_message( $return, sprintf( __( 'Error, could not read <code>%s</code>.', 'secupress' ), $plugin_list ) );

		}

		// check hello.php
		if ( file_exists( dirname( plugin_dir_path( SECUPRESS_FILE ) ) . '/hello.php' ) ) {
			self::set_status( $return, 'Bad' );
			self::set_message( $return, __( 'You should delete <code>hello.php</code> from your plugin directory.', 'secupress' ) );
		}

		return $return;
	}

	static public function inactive_plugins_themes() {

		$return = array();
		self::set_status( $return, 'Good' );

		// inactive plugins
		$check = array_intersect_key( get_plugins(), array_flip( array_filter( array_keys( get_plugins() ), 'is_plugin_inactive' ) ) );
		if ( count( $check ) ) {
			$number = _n( '<b>%d deactivated plugin</b>, if you don\'t need it, delete it: <code>%s</code>', '<b>%d deactivated plugins</b>, if you don\'t need them, delete them: <code>%s</code>', count( $check ), 'secupress' );
			self::set_status( $return, 'Bad' );
			self::set_message( $return, sprintf( $number, count( $check ), implode( '</code>, <code>', wp_list_pluck( $check, 'Name' ) ) ) );
		}

		// inactive themes
		$check = array_diff( wp_list_pluck( wp_get_themes(), 'Name' ), array( wp_get_theme()->Name ) );
		if ( count( $check ) ) {
			$number = _n( '<b>%d deactivated theme</b>, if you don\'t need it, delete it: <code>%s</code>', '<b>%d deactivated themes</b>, if you don\'t need them, delete them: <code>%s</code>', count( $check ), 'secupress' );
			self::set_status( $return, 'Bad' );
			self::set_message( $return, sprintf( $number, count( $check ), implode( '</code>, <code>', $check ) ) );
		}

		return $return;

	}

	static public function auto_update_check() {

		$return = array();
		self::set_status( $return, 'Good' );

		require_once( ABSPATH . 'wp-admin/includes/class-wp-upgrader.php' );
		$WP_Automatic_Updater = new WP_Automatic_Updater();
		$check = (bool) $WP_Automatic_Updater->is_disabled();
		if ( $check ) {
			self::set_status( $return, 'Bad' );
			self::set_message( $return, __( 'Your installation <b>can NOT auto update</b> itself.', 'secupress' ) );
		}

		return $return;

	}

	static public function wp_config_check() {
		$return = array();
		self::set_status( $return, 'Good' );

		// check db prefix
		global $wpdb;
		$check = $wpdb->prefix == 'wp_' || $wpdb->prefix == 'wordpress_';
		if ( $check ) {
			self::set_status( $return, 'Bad' );
			self::set_message( $return, sprintf( __( 'The database prefix shouldn\'t be <code>%s</code>.', 'secupress' ), $wpdb->prefix ) );
		}

		// COOKIEHASH
		$check = defined( 'COOKIEHASH' ) && COOKIEHASH === md5( get_site_option( 'siteurl' ) );
		if ( $check ) {
			self::set_status( $return, 'Bad' );
			self::set_message( $return, sprintf( __( '<code>%1$s</code> shouldn\'t be set with the default value.', 'secupress' ), 'COOKIEHASH' ) );
		}

		// NOBLOGREDIRECT ////
		$check = is_multisite() && defined( 'NOBLOGREDIRECT' ) && '' != ( NOBLOGREDIRECT ) && home_url() != NOBLOGREDIRECT;
		self::set_status( $return, $check ? 'Warning' : 'Good' );
		self::set_message( $return, $check ? sprintf( __( '<code>%1$s</code> shouldn\'t be set.', 'secupress' ), 'NOBLOGREDIRECT' ) : '' );

		// other constants
		$constants = array( 'WP_DEBUG' => false, 'SCRIPT_DEBUG' => false, 'WP_DEBUG_LOG' => 1, 'RELOCATE' => false,
			'DIEONDBERROR' => false, 'WP_DEBUG_DISPLAY' => false, 'ALLOW_UNFILTERED_UPLOADS' => false,
			'FORCE_SSL_ADMIN' => 1, 'FORCE_SSL_LOGIN' => 1, 'DISALLOW_FILE_EDIT' => 1,
			'WP_ALLOW_REPAIR' => '!isset', 'ERRORLOGFILE' => '!empty', 'DISALLOW_UNFILTERED_HTML' => 1,
			'FS_CHMOD_FILE' => 644, 'FS_CHMOD_DIR' => 755,
		);
		foreach( $constants as $value => $compare ) {
			$check = defined ( $value ) ? constant( $value ) : null;
			switch( $compare ) {
				case '!empty':
					if ( '' == ( $check ) ) {
						self::set_status( $return, 'Bad' );
						self::set_message( $return, sprintf( __( '<code>%1$s</code> shouldn\'t be empty.', 'secupress' ), $value ) );
					}
					break;
				case '!isset':
					if ( ! is_null( $check ) ) {
						self::set_status( $return, 'Bad' );
						self::set_message( $return, sprintf( __( '<code>%1$s</code> shouldn\'t be set.', 'secupress' ), $value ) );
					}
					break;
				case 1:
					if ( ! $check ) {
						self::set_status( $return, 'Bad' );
						self::set_message( $return, sprintf( __( '<code>%1$s</code> should be set on %2$s.', 'secupress' ), $value, '<code>true</code>' ) );
					}
					break;
				case false:
					if ( $check ) {
						self::set_status( $return, 'Bad' );
						self::set_message( $return, sprintf( __( '<code>%1$s</code> should be set on %2$s.', 'secupress' ), $value, '<code>false</code>' ) );
					}
					break;
				default:
					$check = decoct( $check ) <= $compare;
					if ( ! $check ) {
						self::set_status( $return, 'Bad' );
						self::set_message( $return, sprintf( __( '<code>%1$s</code> should be set on %2$s or less.', 'secupress' ), $value, '<code>0' . $compare . '</code>' ) );
					}
					break;
			}
		}

		return $return;
	}

	static public function chmods() {////
		$return = array();
		self::set_status( $return, 'Good' );
		$_wp_upload_dir = wp_upload_dir();
		$files = array(	secupress_find_wpconfig_path() 	=> 444,
			get_home_path() . '/'			=> 755,
			get_home_path() . 'wp-admin/' 	=> 755,
			get_home_path() . 'wp-includes/'=> 755,
			WP_CONTENT_DIR 					=> 755,
			get_theme_root() 				=> 755,
			plugin_dir_path( SECUPRESS_FILE )=> 755,
			$_wp_upload_dir['basedir'] 		=> 755,
			$_wp_upload_dir['basedir'] 		=> 755,
		);
		if ( $GLOBALS['is_apache'] ) {
			$files[ get_home_path() . '.htaccess' ] = 444;
		}

		foreach ( $files as $file => $chmod ) {
			$check = decoct(fileperms($file) & 0777);

			if (!$check) {
				self::set_status($return, 'Warning');
				self::set_message($return, sprintf(__('Unable to determine status of <code>%s</code>.', 'secupress'), $file));
			} elseif ($check > $chmod) {
				self::set_status($return, 'Bad');
				self::set_message($return, sprintf(__('<code>%1$s</code> file permissions set on %2$s, NOT %3$s!', 'secupress'), str_replace( ABSPATH, '', $file), '<code>0' . $chmod . '</code>', '<code>0' . $check . '</code>'));
			}
		}
		return $return;
	}

	static public function disclose_check() {
		$return = array();
		self::set_status( $return, 'Good' );

		// Generator meta tag + php header
		$response = wp_remote_get( home_url(), self::$remote_args );
		if ( ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response )) {
			$html = wp_remote_retrieve_body( $response );
			$head = wp_remote_retrieve_header( $response, 'x-powered-by' );
			if ( strpos( $head, phpversion() ) !== false ) {
				self::set_status( $return, 'Bad' );
				self::set_message( $return, __( 'The website displays the <b>PHP version</b> in the request headers.', 'secupress' ) );
			}
			// find all Meta Tags
			preg_match_all( '#<meta[^>]*[name="generator"]?[^>]*content="WordPress ' . get_bloginfo( 'version' ) . '"[^>]*[name="generator"]?[^>]*>#si', $html, $matches );
			if ( count( array_filter( $matches ) ) ) {
				self::set_status( $return, 'Bad' );
				self::set_message( $return, __( 'The website displays the <b>WordPress version</b> in the homepage source code.', 'secupress' ) . ' (META)' );
			}
		} else {
			self::set_status( $return, 'Warning' );
			self::set_message( $return, __( 'Unable to determine status of your homepage.', 'secupress' ) );
		}


		// meta generator is hidden, what about style loader now?
		if ( 'Good' == $return['status'] ) {
			$check = home_url( '/fake.css?ver=' . get_bloginfo( 'version' ) ) == apply_filters( 'style_loader_src', home_url( '/fake.css?ver=' . get_bloginfo( 'version' ) ), 'secupress' );
			if ( $check ) {
				self::set_status( $return, 'Bad' );
				self::set_message( $return, __( 'The website displays the <b>WordPress version</b> in the homepage source code.', 'secupress' ) . ' (CSS)' );
			}
		}

		// meta generator is hidden, what about script loader now?
		if ( 'Good' == $return['status'] ) {
			$check = home_url( '/fake.js?ver=' . get_bloginfo( 'version' ) ) == apply_filters( 'script_loader_src', home_url( '/fake.js?ver=' . get_bloginfo( 'version' ) ), 'secupress' );
			if ( $check ) {
				self::set_status( $return, 'Bad' );
				self::set_message( $return, __( 'The website displays the <b>WordPress version</b> in the homepage source code.', 'secupress' ) . ' (JS)' );
			}
		}

		// meta generator is hidden, style and css files doesn't contains it neither, what about full source page?
		if ( 'Good' == $return['status'] ) {
			if ( ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response ) ) { // response from the 1st call
				$check = strpos( wp_remote_retrieve_body( $response ), get_bloginfo( 'version' ) );
				if ( $check ) {
					self::set_status( $return,'Bad' );
					self::set_message( $return, __( 'The website displays the <b>WordPress version</b> in the homepage source code.', 'secupress' ) );
				}
			} else {
				self::set_status( $return, 'Warning' );
				self::set_message( $return, __( 'Unable to determine status of your homepage.', 'secupress' ) );
			}
		}

		// Readme file
		$response = wp_remote_get( home_url( 'readme.html' ), self::$remote_args );
		if ( ! is_wp_error( $response ) ) {
			if ( 200 === wp_remote_retrieve_response_code( $response ) ) {
				self::set_status( $return, 'Bad' );
				self::set_message( $return, sprintf( __( '<code>%s</code> shouldn\'t be accessible by anyone.', 'secupress' ), home_url( 'readme.html' ) ) );
			}
		} else {
			self::set_status( $return, 'Warning' );
			self::set_message( $return, sprintf( __( 'Unable to determine status of <code>%s</code>.', 'secupress' ), home_url( 'readme.html' ) ) );
		}

		return $return;
	}

	static function php_disclosure() {
		$return = array();
		self::set_status( $return, 'Good' );

		// Easter egg
		$response = wp_remote_get( home_url( '/?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000' ), self::$remote_args );
		if ( ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response ) && $body = wp_remote_retrieve_body( $response ) ) {
			if ( strpos( $body, '<h1>PHP Credits</h1>' ) > 0 && strpos( $body, '<title>phpinfo()</title>' ) > 0 ) {
				self::set_status( $return, 'Bad' );
				self::set_message( $return, sprintf( __( '<code>%s</code> shouldn\'t be accessible by anyone.', 'secupress' ), home_url( '/?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000' ) ) );
			}
		} else {
			self::set_status( $return, 'Warning' );
			self::set_message( $return, sprintf( __( 'Unable to determine status of <code>%s</code>.', 'secupress' ), home_url( '/?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000' ) ) );
		}

		return $return;
	}

	static function directory_listing() {
		$return = array();
		self::set_status( $return, 'Good' );

		// Directory listing
		$_wp_upload_dir = wp_upload_dir();
		$base_url = $_wp_upload_dir['baseurl'];
		$response = wp_remote_get( $base_url, self::$remote_args );
		if ( ! is_wp_error( $response ) ) {
			if ( 200 === wp_remote_retrieve_response_code( $response ) ) {
				self::set_status( $return, 'Bad' );
				self::set_message( $return, sprintf( __( '<code>%s</code> shouldn\'t be accessible by anyone.', 'secupress' ), $base_url ) );
			}
		} else {
			self::set_status( $return, 'Warning' );
			self::set_message( $return, sprintf( __( 'Unable to determine status of <code>%s</code>.', 'secupress' ), $base_url ) );
		}

		return $return;
	}


	static function login_errors_disclose() {
		$return = array();
		self::set_status( $return, 'Good' );

		// Login errors
		$check = apply_filters( 'login_errors', 'errors' );
		if ( 'errors' === $check ) {
			self::set_status( $return,  'Bad' );
			self::set_message( $return, __( '<b>Login errors</b> shouldn\'t be displayed.', 'secupress' ) );
		}

		return $return;
	}

	static public function salt_keys_check() {
		$return = $bad_keys = array();
		self::set_status( $return, 'Good' );

		$schemes = array( 'key', 'salt' );

		$keys = array(
			'auth',
			'secure_auth',
			'logged_in',
			'nonce',
		);

		// get code only from wp-config.php
		$wp_config_content = self::remove_comments( file_get_contents( secupress_find_wpconfig_path() ) );
		preg_match_all( '/' . implode( '|', $keys ) . '/', $wp_config_content, $matches );
		$bad_keys['hardcoded'] = isset( $matches[0] ) ? reset( $matches ) : array();

		foreach ( $schemes as $scheme ) {
			foreach ( $keys as $key ) {

				// Check constant
				$check = sprintf( '%1$s_%2$s', strtoupper( $key ), strtoupper( $scheme ) );
				$constant = defined( $check ) ? constant( $check ) : null;
				switch( true ) {
					case is_null( $constant ) :
						$bad_keys['notset'][] = $check;
						break;
					case 'put your unique phrase here' == $constant :
						$bad_keys['default'][] = $check;
						break;
					case strlen( $constant ) < 64 :
						$bad_keys['tooshort'][] = $check;
						break;
				}

				// Check DB
				$check = sprintf( '%1$s_%2$s', strtolower( $key ), strtolower( $scheme ) );
				$db = get_site_option( $check, null );
				if ( ! is_null( $db ) ) {
					$bad_keys['db'][] = $check;
				}
			}
		}

		if ( count( array_filter( $bad_keys ) ) ) {
			self::set_status( $return, 'Bad' );
			$bad_keys_text = '';
			$l10n_reasons = array( 	'notset' 	=> __( 'Not Set:', 'secupress' ),
				'default' 	=> __( 'Default Value:', 'secupress' ),
				'tooshort' 	=> __( 'Too Short:', 'secupress' ),
				'hardcoded'	=> __( 'Hardcoded:', 'secupress' ),
				'db'		=> __( 'From DB:', 'secupress' ),
			);
			foreach ( $l10n_reasons as $reason => $l10n_text ) {
				if ( count( $bad_keys[ $reason ] ) ) {
					$bad_keys_text .= '<p><b>&middot; ' . $l10n_text . '</b> <code>' . implode( '</code>, <code>', $bad_keys[ $reason ] ) . '</code>.</p>';
				}
			}
			self::set_message( $return, sprintf( __( 'The following security keys aren\'t correctly set: %s', 'secupress' ), $bad_keys_text ) );
		}

		return $return;
	}

	static public function passwords_strenght() {
		$return = array();
		self::set_status( $return, 'Good' );

		// DB_PASSWORD
		if ( '' == ( DB_PASSWORD ) ) {
			self::set_status( $return, 'Bad' );
			self::set_message( $return, __( '<code>DB_PASSWORD</code> is <b>empty</b>.', 'secupress' ) );
		} elseif ( self::dictionary_attack( DB_PASSWORD ) ) {
			self::set_status( $return, 'Bad' );
			self::set_message( $return, __( '<code>DB_PASSWORD</code> is known as a <b>too common</b> one.', 'secupress' ) );
		} elseif ( strlen( DB_PASSWORD ) <= 6 ) {
			self::set_status( $return, 'Bad' );
			self::set_message( $return, __( '<code>DB_PASSWORD</code> <b>%d chars</b>.', 'secupress' ), strlen( DB_PASSWORD ) );
		} elseif ( sizeof( count_chars( DB_PASSWORD, 1 ) ) < 5 ) {
			self::set_status( $return, 'Bad' );
			self::set_message( $return, __( '<code>DB_PASSWORD</code> isn\'t <b>complex</b> enough.', 'secupress' ) );
		}

		// FTP_PASS
		if ( defined( 'FTP_PASS' ) ) {
			if ( '' == ( FTP_PASS ) ) {
				self::set_status( $return, 'Bad' );
				self::set_message( $return, __( '<code>FTP_PASS</code> is <b>empty</b>.', 'secupress' ) );
			} elseif ( self::dictionary_attack( FTP_PASS ) ) {
				self::set_status( $return, 'Bad' );
				self::set_message( $return, __( '<code>FTP_PASS</code> is known as a <b>too common</b> one.', 'secupress' ) );
			} elseif ( strlen( FTP_PASS ) <= 6 ) {
				self::set_status( $return, 'Bad' );
				self::set_message( $return, __( '<code>FTP_PASS</code> is only <b>%d chars</b>.', 'secupress' ), strlen( FTP_PASS ) );
			} elseif ( sizeof( count_chars( FTP_PASS, 1 ) ) < 5 ) {
				self::set_status( $return, 'Bad' );
				self::set_message( $return, __( '<code>FTP_PASS</code> isn\'t <b>complex</b> enough.', 'secupress' ) );
			}
		}

		return $return;
	}

	static function bad_user_agent() {
		$return = array();
		self::set_status( $return, 'Good' );

		// bad user agent
		$response = wp_remote_get( home_url(), array_merge( self::$remote_args, array( 'user-agent' => '<script>' ) ) );
		if ( ! is_wp_error( $response ) ) {
			if ( 200 === wp_remote_retrieve_response_code( $response ) ) {
				self::set_status( $return, 'Bad' );
				self::set_message( $return, sprintf( __( 'Your website should block <code>%s</code> requests with <b>bad user-agents</b>.', 'secupress' ), 'HTTP' ) );
			}
		} else {
			self::set_status( $return, 'Warning' );
			self::set_message( $return, __( 'Unable to determine status of your homepage.', 'secupress' ) );
		}

		return $return;
	}

	static function bad_request_methods() {
		$return = array();
		self::set_status( $return, 'Good' );

		// disallowed requests methods
		$methods = array( 'TRACE', 'TRACK', 'HEAD', 'PUT', 'OPTIONS', 'DELETE', 'CONNECT' );
		foreach ( $methods as $method ) {
			//$WP_HTTP = _wp_http_get_object();
			$response = wp_remote_request( home_url(), array( 'method' => $method, 'redirection' => false ) );
			if ( ! is_wp_error( $response ) ) {
				if ( 200 === wp_remote_retrieve_response_code( $response ) && '' != wp_remote_retrieve_body( $response ) ) {
					self::set_status( $return, 'Bad' );
					self::set_message( $return, sprintf( __( 'Your website should block <code>%s</code> request method.', 'secupress' ), $method ) );
				}
			} else {
				self::set_status( $return, 'Warning' );
				self::set_message( $return, __( 'Unable to determine status of your homepage.', 'secupress' ) );
			}
		}

		return $return;
	}

	static function common_flaws() {
		$return = $hashes = array();

		// Scanners and Breach
		for ( $i = 0 ; $i < 3 ; ++$i ) {
			$response = wp_remote_get( home_url( '/?' . uniqid( 'time=', true ) ), self::$remote_args );
			if ( ! is_wp_error( $response ) ) {
				if ( 200 === wp_remote_retrieve_response_code( $response ) ) {
					$hashes[] = md5( wp_remote_retrieve_body( $response ) );
				}
			}
		}
		$hashes = array_unique( $hashes );
		if ( count( $hashes ) === 3 ) {
			self::set_status( $return, 'Good' );
		} elseif( count( $hashes ) === 0 ) {
			self::set_status( $return, 'Warning' );
			self::set_message( $return, __( 'Unable to determine status of your homepage.', 'secupress' ) );
		} else { // 1 or 2
			self::set_status( $return, 'Bad' );
			self::set_message( $return, __( 'Your website pages should be <b>different</b> for each reload.', 'secupress' ) );
		}

		// Shellshock
		// from http://plugins.svn.wordpress.org/shellshock-check/trunk/shellshock-check.php
		if ( strtoupper( substr( PHP_OS, 0, 3 ) ) !== 'WIN' ) {

			$env = array( 'SHELL_SHOCK_TEST' => '() { :;}; echo VULNERABLE' );

			$desc = array(
				0 => array( 'pipe', 'r' ),
				1 => array( 'pipe', 'w' ),
				2 => array( 'pipe', 'w' ),
			);

			// CVE-2014-6271
			$p = proc_open( 'bash -c "echo Test"', $desc, $pipes, null, $env );
			$output = isset( $pipes[1] ) ? stream_get_contents( $pipes[1] ) : 'error';
			proc_close( $p );

			if ( strpos( $output, 'VULNERABLE' ) === false ) {
				self::set_status( $return, 'Good' );
			} elseif ( 'error' === $output ) {
				self::set_status( $return, 'Warning' );
				self::set_message( $return, __( 'Unable to determine status of Shellshock flaw.', 'secupress' ) );
			} else {
				self::set_status( $return, 'Bad' );
				self::set_message( $return, sprintf( __( 'The server appears to be vulnerable to Shellshock (%s).', 'secupress' ), '<i>CVE-2014-6271</i>' ) );
			}

			// CVE-2014-7169
			$p = proc_open("rm -f echo; env 'x=() { (a)=>\' bash -c \"echo date +%Y\"; cat echo", $desc, $pipes, sys_get_temp_dir() );
			$output = isset( $pipes[1] ) ? stream_get_contents( $pipes[1] ) : 'error';
			proc_close( $p );

			$test_date = date('Y');

			if ( trim( $output ) !== $test_date ) {
				self::set_status( $return, 'Good' );
			} elseif ( 'error' === $output ) {
				self::set_status( $return, 'Warning' );
				self::set_message( $return, __( 'Unable to determine status of <b>Shellshock</b> flaw.', 'secupress' ) );
			} else {
				self::set_status( $return, 'Bad' );
				self::set_message( $return, sprintf( __( 'The server appears to be vulnerable to <b>Shellshock</b> (%s).', 'secupress' ), '<i>CVE-2014-7169</i>' ) );
			}

		}

		// wp-config.php access
		$response = wp_remote_get( home_url( '/?' . time() . '=wp-config.php' ), self::$remote_args );
		if ( ! is_wp_error( $response ) ) {
			if ( 200 === wp_remote_retrieve_response_code( $response ) ) {
				self::set_status( $return, 'Bad' );
				self::set_message( $return, sprintf( __( 'Your website should block <b>malicious requests</b>.', 'secupress' ), 'HTTP' ) );
			}
		} else {
			self::set_status( $return, 'Warning' );
			self::set_message( $return, __( 'Unable to determine status of your homepage.', 'secupress' ) );
		}

		return $return;
	}

	static function block_long_url() {
		$return = array();
		self::set_status( $return, 'Good' );

		// too long URL
		$response = wp_remote_get( home_url( '/?' . time() . '=' . wp_generate_password( 255, false ) ), self::$remote_args );
		if ( ! is_wp_error( $response ) ) {
			if ( 200 === wp_remote_retrieve_response_code( $response ) ) {
				self::set_status( $return, 'Bad' );
				self::set_message( $return, sprintf( __( 'Your website should block <b>too long string requests</b>.', 'secupress' ), 'HTTP' ) );
			}
		} else {
			self::set_status( $return, 'Warning' );
			self::set_message( $return, __( 'Unable to determine status of your homepage.', 'secupress' ) );
		}

		return $return;

	}

	static function test_sqli() {
		$return = array();
		self::set_status( $return, 'Good' );

		// SQLi attemps
		$response = wp_remote_get( home_url( '/?' . time() . '=UNION+SELECT+FOO' ), self::$remote_args );
		if ( ! is_wp_error( $response ) ) {
			if ( 200 === wp_remote_retrieve_response_code( $response ) ) {
				self::set_status( $return, 'Bad' );
				self::set_message( $return, sprintf( __( 'Your website should block <b>malicious requests</b>.', 'secupress' ), 'HTTP' ) );
			}
		} else {
			self::set_status( $return, 'Warning' );
			self::set_message( $return, __( 'Unable to determine status of your homepage.', 'secupress' ) );
		}

		return $return;

	}

	static function block_http_10() {
		$return = array();
		self::set_status( $return, 'Good' );

		// disallow HTTP 1.0 POST
		$response = wp_remote_post( home_url(), array( 'httpversion' => '1.0' ) );
		if ( ! is_wp_error( $response ) ) {
			if ( 200 === wp_remote_retrieve_response_code( $response ) ) {
				self::set_status( $return, 'Bad' );
				self::set_message( $return, sprintf( __( 'Your website should block <code>%s</code> requests.', 'secupress' ), 'HTTP/1.0 POST' ) );
			}
		} else {
			self::set_status( $return, 'Warning' );
			self::set_message( $return, __( 'Unable to determine status of your homepage.', 'secupress' ) );
		}

		return $return;

	}

}