<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Get the blacklisted usernames.
 *
 * @since 1.0
 *
 * @return (array)
 */
function secupress_get_blacklisted_usernames() {
	// Blacklisted usernames.
	$list = array(
		'a', 'about', 'access', 'account', 'accounts', 'ad', 'address', 'adm', 'administration', 'adult', 'advertising', 'affiliate', 'affiliates', 'ajax', 'analytics', 'android', 'anon', 'anonymous', 'api', 'app', 'apps', 'archive', 'atom', 'auth', 'authentication', 'avatar',
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
		's', 'sale', 'sales', 'sample', 'samples', 'script', 'scripts', 'secure', 'send', 'service', 's' . 'e' . 'x', 'shop', 'sql', 'signup', 'signin', 'search', 'security', 'settings', 'setting', 'setup', 'site', 'sites', 'sitemap', 'smtp', 'soporte', 'ssh', 'stage', 'staging', 'start', 'subscribe', 'subdomain', 'suporte', 'support', 'stat', 'static', 'stats', 'status', 'store', 'stores', 'system',
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

	/**
	 * Filter the list of blacklisted usernames.
	 *
	 * @since 1.0
	 *
	 * @param (array) $list List of usernames.
	 */
	$list = apply_filters( 'secupress.plugin.blacklist_logins_list', $list );

	// Temporarily allow some blacklisted usernames.
	$allowed = (array) secupress_cache_data( 'allowed_usernames' );
	if ( $allowed ) {
		$list = array_diff( $list, $allowed );
		secupress_cache_data( 'allowed_usernames', array() );
	}

	return $list;
}


/**
 * Related to the non login timeslot submodule, tell if we're in the timeslot.
 *
 * @since 1.0
 *
 * @return (bool)
 */
function secupress_in_timeslot() {
	$timings = secupress_get_module_option( 'login-protection_nonlogintimeslot', false, 'users-login' );

	if ( ! $timings || ! is_array( $timings ) ) {
		return false;
	}

	// Server hour.
	$utc    = new DateTimeZone( 'UTC' );
	$new_tz = ini_get( 'date.timezone' );
	$new_tz = $new_tz ? new DateTimeZone( $new_tz ) : $utc;
	$date   = new DateTime( '', $utc );
	$date->setTimezone( $new_tz );
	$server_hour  = strtotime( $date->format( 'Y-m-d H:i:s' ) );
	// From.
	$setting_from = strtotime( date( sprintf( 'Y-m-d %s:%s:00', str_pad( $timings['from_hour'], 2, '0', STR_PAD_LEFT ), str_pad( $timings['from_minute'], 2, '0', STR_PAD_LEFT ) ) ) );
	// To.
	$setting_to   = strtotime( date( sprintf( 'Y-m-d %s:%s:00', str_pad( $timings['to_hour'], 2, '0', STR_PAD_LEFT ), str_pad( $timings['to_minute'], 2, '0', STR_PAD_LEFT ) ) ) );

	if ( ( $setting_from < $setting_to ) && ( $server_hour > $setting_from && $server_hour < $setting_to ) ||
		 ( $setting_from > $setting_to ) && ( $server_hour > $setting_from || $server_hour < $setting_to ) ) {
		return true;
	}

	return false;
}
