<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Bad Usernames scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */

class SecuPress_Scan_Bad_Usernames extends SecuPress_Scan {

	const VERSION = '1.0';

	protected static $name = 'bad_usernames';
	public    static $prio = 'medium';


	public function __construct() {
		if ( self::$instance ) {
			return self::$instance;
		}

		self::$type  = 'WordPress';
		self::$title = __( 'Check if your users got correct username, not blacklisted, not the same as their login.', 'secupress' );
		self::$more  = __( 'It\'s important to not having the same login and display name to protect your login name and avoid simple brute-force attacks on it.', 'secupress' );
	}


	public static function get_messages( $id = null ) {
		$messages = array(
			// good
			0   => __( 'All your users\' names are correct.', 'secupress' ),
			// bad
			200 => _n_noop( '<strong>%d</strong> user has a forbidden login name.', '<strong>%d</strong> users have a forbidden login name.', 'secupress' ),
			201 => _n_noop( '<strong>%d</strong> user has similar login name and display name.', '<strong>%d</strong> users have similar login name and display name.', 'secupress' ),
			// cantfix
			300 => __( 'I can not fix this, you have to do it yourself, have fun.', 'secupress' ),
		);

		if ( isset( $id ) ) {
			return isset( $messages[ $id ] ) ? $messages[ $id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	public function scan() {
		global $wpdb;

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

		$ids = $wpdb->get_col( 'SELECT ID from ' . $wpdb->users . ' WHERE user_login IN ( "' . implode( '", "', $names ) . '" )' );
		$ids = count( $ids );

		if ( $ids ) {
			// bad
			$this->add_message( 200, array( $ids, number_format_i18n( $ids ) ) );
		}

		// Who got the same nickname and login?
		$ids = $wpdb->get_col( "SELECT ID FROM $wpdb->users u, $wpdb->usermeta um WHERE u.user_login = u.display_name OR ( um.user_id = u.ID AND um.meta_key = 'nickname' AND um.meta_value = u.user_login ) GROUP BY ID" );
		$ids = count( $ids );

		if ( $ids ) {
			// bad
			$this->add_message( 201, array( $ids, number_format_i18n( $ids ) ) );
		}

		// good
		$this->maybe_set_status();

		return parent::scan();
	}


	public function fix() {

		// include the fix here.

		return parent::fix();
	}
}
