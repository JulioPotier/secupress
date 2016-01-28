<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Bad Usernames scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */

class SecuPress_Scan_Bad_Usernames extends SecuPress_Scan implements iSecuPress_Scan {

	const VERSION = '1.0';

	/**
	 * @var Singleton The reference to *Singleton* instance of this class
	 */
	protected static $_instance;
	public    static $prio = 'medium';


	protected static function init() {
		self::$type  = 'WordPress';
		self::$title = __( 'Check if your users username are not blacklisted.', 'secupress' );
		self::$more  = __( 'Some usernames are known to be used for malicious usage, or created by bots.', 'secupress' );
	}


	public static function get_messages( $message_id = null ) {
		$messages = array(
			// good
			0   => __( 'All the user names are correct.', 'secupress' ),
			1   => __( 'Module activated: the users with a blacklisted username will be asked to change it.', 'secupress' ),
			// bad
			200 => _n_noop( '<strong>%s user</strong> has a forbidden username: %s', '<strong>%s users</strong> have a forbidden username: %s', 'secupress' ),
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	public function scan() {
		global $wpdb;

		// Blacklisted names
		$names  = static::_get_blacklisted_usernames();
		$logins = $wpdb->get_col( "SELECT user_login from $wpdb->users WHERE user_login IN ( '$names' )" );
		$ids    = count( $logins );

		// bad
		if ( $ids ) {
			$this->slice_and_dice( $logins, 10 );
			// 2nd param: 1st item is used for the noop if needed, the rest for sprintf.
			$this->add_message( 200, array( $ids, $ids, static::wrap_in_tag( $logins, 'strong' ) ) );
		}

		// good
		$this->maybe_set_status( 0 );

		return parent::scan();
	}


	public function fix() {
		global $wpdb;

		// Blacklisted names
		$names = static::_get_blacklisted_usernames();
		$ids   = $wpdb->get_col( "SELECT ID from $wpdb->users WHERE user_login IN ( '$names' )" );

		if ( $ids ) {
			$settings = array( 'blacklist-logins_activated' => 1 );
			secupress_activate_module( 'users-login', $settings );
			// good
			$this->add_fix_message( 1 );
		}

		// good
		$this->maybe_set_fix_status( 0 );

		return parent::fix();
	}


	/*
	 * Get the blacklisted usernames.
	 *
	 * @since 1.0
	 * @see `secupress_get_blacklisted_usernames()` in /inc/modules/users-login/plugins/blacklist-logins.php
	 *
	 * @return (string) A comma separated list of blacklisted usernames.
	 */
	final protected static function _get_blacklisted_usernames() {
		// Blacklisted usernames.
		$list = array(
			'a', 'admin', 'about', 'access', 'account', 'accounts', 'ad', 'address', 'adm', 'administration', 'adult', 'advertising', 'affiliate', 'affiliates', 'ajax', 'analytics', 'android', 'anon', 'anonymous', 'api', 'app', 'apps', 'archive', 'atom', 'auth', 'authentication', 'avatar',
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
			'z',
			'_', '.', '-', '@',
			'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
		);

		$list = apply_filters( 'secupress.plugin.blacklist_logins_list', $list );

		// Temporarily allow some blacklisted usernames.
		$allowed = (array) secupress_cache_data( 'allowed_usernames' );
		if ( $allowed ) {
			$list = array_diff( $list, $allowed );
			secupress_cache_data( 'allowed_usernames', array() );
		}

		return implode( "','", $list );
	}
}
