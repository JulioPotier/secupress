<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Bad URL Access scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */

class SecuPress_Scan_Bad_URL_Access extends SecuPress_Scan implements iSecuPress_Scan {

	const VERSION = '1.0';

	/**
	 * @var Singleton The reference to *Singleton* instance of this class
	 */
	protected static $_instance;
	public    static $prio = 'medium';


	protected static function init() {
		self::$type  = 'WordPress';
		self::$title = __( 'Check if your WordPress site discloses sensitive informations.', 'secupress' );
		self::$more  = __( 'When an attacker wants to hack into a WordPress site, he will search for a maximum of information. His goal is to find outdated versions of your server softwares or WordPress component. Don\'t let him easily find these informations.', 'secupress' );
	}


	public static function get_messages( $message_id = null ) {
		global $is_nginx;
		$nginx_rules = '';

		if ( $is_nginx ) {
			$bases = secupress_get_rewrite_bases();
			$nginx_rules = 'location ~ ^(' . $bases['home_from'] . 'php\.ini|' . $bases['site_from'] . WPINC . '/.+\.php|' . $bases['site_from'] . "wp-admin/(admin-functions|install|menu-header|setup-config|([^/]+/)?menu|upgrade-functions|includes/.+)\.php)$ {\n\treturn 404;\n}";
		}

		$messages = array(
			// good
			0   => __( 'Your site does not reveal sensitive informations.', 'secupress' ),
			1   => __( 'Your %s file has been successfully edited.', 'secupress' ),
			2   => _n_noop( 'The following file has been successfully edited: %s.', 'The following files have been successfully edited: %s.', 'secupress' ),
			// warning
			100 => __( 'Unable to determine status of %s.', 'secupress' ),
			// bad
			200 => _n_noop( '%s should not be accessible by anyone.', '%s should not be accessible by anyone.', 'secupress' ),
			// cantfix
			/* translators: 1 is a block name, 2 is a file name, 3 is some code */
			300 => sprintf( __( 'Your server runs a nginx system, these sensitive informations disclosures cannot be fixed automatically but you can do it yourself by adding the following code inside the %1$s block of your %2$s file: %3$s.', 'secupress' ), '"server"', '<code>nginx.conf</code>', "<pre>$nginx_rules</pre>" ),
			301 => __( 'Your server runs a non recognized system. These sensitive informations disclosures cannot be fixed automatically.', 'secupress' ),
			/* translators: 1 si a file name, 2 is some code */
			302 => __( 'Your %1$s file is not writable. Please add the following lines at the beginning of the file: %2$s', 'secupress' ),
			303 => _n_noop( 'The following file is not writable. Please add the those lines at the beginning of the file: %s', 'The following files are not writable. Please add the those lines at the beginning of each file: %s', 'secupress' ),
			304 => __( 'It seems URL rewriting is not enabled on your server. The sensitive information disclosure cannot be fixed.', 'secupress' ),
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	public function scan() {
		// Avoid plugin's hooks.
		remove_all_filters( 'site_url' );
		remove_all_filters( 'includes_url' );
		remove_all_filters( 'admin_url' );
		remove_all_filters( 'home_url' );

		$bads     = array();
		$warnings = array();
		$urls     = array(
			home_url( 'php.ini' ),
			admin_url( 'install.php' ),
			admin_url( 'includes/comment.php' ),
			admin_url( 'network/menu.php' ),
			admin_url( 'user/menu.php' ),
			includes_url( 'admin-bar.php' ),
		);

		foreach ( $urls as $url ) {
			$response = wp_remote_get( $url, array( 'redirection' => 0 ) );

			if ( ! is_wp_error( $response ) ) {

				if ( 200 === wp_remote_retrieve_response_code( $response ) ) {
					// bad
					$bads[] = '<code>' . $url . '</code>';
				}

			} else {
				// warning
				$warnings[] = '<code>' . $url . '</code>';
			}
		}

		if ( $bads ) {
			// bad
			$this->add_message( 200, array( count( $bads ), $bads ) );
		}

		if ( $warnings ) {
			// warning
			$this->add_message( 100, array( count( $warnings ), $warnings ) );
		}

		// good
		$this->maybe_set_status( 0 );

		return parent::scan();
	}


	public function fix() {
		global $is_apache, $is_nginx, $is_iis7;

		if ( $is_apache ) {
			$this->fix_apache();
		} elseif ( $is_iis7 ) {
			$this->fix_iis7();
		} elseif ( $is_nginx ) {
			$this->add_fix_message( 300 );
		} else {
			$this->add_fix_message( 301 );
		}

		return parent::fix();
	}


	protected function fix_apache() {
		/*
		 * ^php\.ini$
		 *
		 * ^wp-admin/admin-functions\.php$
		 * ^wp-admin/install\.php$
		 * ^wp-admin/menu-header\.php$
		 * ^wp-admin/menu\.php$
		 * ^wp-admin/setup-config\.php$
		 * ^wp-admin/upgrade-functions\.php$
		 *
		 * ^wp-admin/includes/.+\.php$
		 *
		 * ^wp-admin/network/menu\.php$
		 *
		 * ^wp-admin/user/menu\.php$
		 *
		 * ^wp-includes/.+\.php$
		 */
		$marker = 'bad_url_access';
		$bases  = secupress_get_rewrite_bases();

		// We can use rewrite rules \o/
		if ( got_mod_rewrite() ) {
			$base   = $bases['base'];
			$match  = '^(' . $bases['home_from'] . 'php\.ini|' . $bases['site_from'] . WPINC . '/.+\.php|' . $bases['site_from'] . 'wp-admin/(admin-functions|install|menu-header|setup-config|([^/]+/)?menu|upgrade-functions|includes/.+)\.php)$';
			// Trigger a 404 error, because forbidding access to a file is nice, but making it also invisible is more fun :)
			$rules  = "<IfModule mod_rewrite.c>\n";
			$rules .= "    RewriteEngine On\n";
			$rules .= "    RewriteBase $base\n";
			$rules .= "    RewriteRule $match [R=404,L]\n";
			$rules .= "</IfModule>\n";

			if ( secupress_write_htaccess( $marker, $rules ) ) {
				// good
				$this->add_fix_message( 1, array( '<code>.htaccess</code>' ) );
			} else {
				// cantfix
				$this->add_fix_message( 302, array( '<code>.htaccess</code>', "<pre># BEGIN SecuPress $marker\n$rules\n# END SecuPress</pre>" ) );
			}
			return;
		}

		// If the rewrite module is disabled (unlikely), forbid access: we have to create a `.htaccess` file in 6 different locations.
		$regexs = array(
			''                                     => 'php.ini',
			$bases['wpdir'] . WPINC . '/'          => '^.+\.php$',
			$bases['wpdir'] . 'wp-admin/'          => '^(admin-functions|install|menu-header|setup-config|menu|upgrade-functions)\.php$',
			$bases['wpdir'] . 'wp-admin/includes/' => '^.+\.php$',
			$bases['wpdir'] . 'wp-admin/network/'  => 'menu\.php',
			$bases['wpdir'] . 'wp-admin/user/'     => 'menu\.php',
		);
		$done = array();
		$fail = array();

		foreach ( $regexs as $path => $regex ) {
			$tag    = strpos( $regex, '^' ) === 0 ? 'FilesMatch' : 'Files';
			$rules  = "<$tag \"$regex\">\n";
			$rules .= "    deny from all\n";
			$rules .= "</$tag>\n";

			if ( secupress_write_htaccess( $marker, $rules, $path ) ) {
				// good
				$done[] = "<code>$path.htaccess</code>";
			} else {
				// cantfix
				$fail[] = "<code>$path.htaccess</code><pre># BEGIN SecuPress $marker\n$rules\n# END SecuPress</pre>";
			}
		}

		if ( $done ) {
			// good
			$this->add_fix_message( 2, array( count( $done ), $done ) );
		}

		if ( $fail ) {
			// cantfix
			$this->add_fix_message( 303, array( count( $fail ), '<br/>' . implode( '', $fail ) ) );
		}
	}


	protected function fix_iis7() {
		if ( ! iis7_supports_permalinks() ) {
			// cantfix
			$this->add_fix_message( 304 );
			return;
		}

		$marker = 'bad_url_access';
		$spaces = str_repeat( ' ', 10 );
		$bases  = secupress_get_rewrite_bases();
		$match  = '^(' . $bases['home_from'] . 'php\.ini|' . $bases['site_from'] . WPINC . '/.+\.php|' . $bases['site_from'] . 'wp-admin/(admin-functions|install|menu-header|setup-config|([^/]+/)?menu|upgrade-functions|includes/.+)\.php)$';

		$node   = "<rule name=\"SecuPress $marker\" stopProcessing=\"true\">\n";
			$node  .= "$spaces  <match url=\"$match\"/>\n";
			$node  .= "$spaces  <action type=\"CustomResponse\" statusCode=\"404\"/>\n";
		$node  .= "$spaces</rule>";

		if ( secupress_insert_iis7_nodes( $marker, array( 'nodes_string' => $node ) ) ) {
			// good
			$this->add_fix_message( 1, array( '<code>web.config</code>' ) );
		} else {
			// cantfix
			$this->add_fix_message( 302, array( '<code>web.config</code>', '<pre>' . $node . '</pre>' ) );
		}
	}
}
