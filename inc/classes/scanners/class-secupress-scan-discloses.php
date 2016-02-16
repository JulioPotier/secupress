<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Discloses scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */

class SecuPress_Scan_Discloses extends SecuPress_Scan implements iSecuPress_Scan {

	const VERSION = '1.0';

	/**
	 * @var Singleton The reference to *Singleton* instance of this class
	 */
	protected static $_instance;
	public    static $prio = 'medium';


	protected static function init() {
		self::$type  = 'WordPress';
		self::$title = __( 'Check if your WordPress site discloses its version.', 'secupress' );
		self::$more  = __( 'When an attacker wants to hack into a WordPress site, he will search for a maximum of informations. His goal is to find outdated versions of your server softwares or WordPress components. Don\'t let them easily find these informations.', 'secupress' );
	}


	public static function get_messages( $message_id = null ) {
		global $is_nginx;

		$nginx_rules = '';

		if ( $is_nginx ) {
			$base         = secupress_get_rewrite_bases();
			$base         = $bases['home_from'];
			$marker       = 'versions_disclose';
			// http://nginx.org/en/docs/http/ngx_http_core_module.html#server_tokens
			$nginx_rules  = "http {\n\t# BEGIN SecuPress $marker 1\n\tserver_tokens off;\n\t# END SecuPress\n}\n";
			// http://nginx.org/en/docs/http/ngx_http_core_module.html#location
			$nginx_rules .= "server {\n\t# BEGIN SecuPress $marker 2\n\tlocation {$base}readme.html {\n\t\treturn 404;\n\t}\n\t# END SecuPress\n}";
		}

		$messages = array(
			// good
			0   => __( 'Your site does not reveal sensitive informations.', 'secupress' ),
			/* translators: 1 and 2 are file names */
			1   => __( 'The rules against the PHP version disclosure and forbidding access to your %1$s file have been successfully added to your %2$s file.', 'secupress' ),
			/* translators: 1 is a file name */
			2   => __( 'As the rules against the PHP version disclosure added to your %s file do not seem to work, a plugin has been activated to remove this information in some other way.', 'secupress' ),
			3   => __( 'The generator meta tag should not be displayed anymore.', 'secupress' ),
			4   => __( 'The WordPress version should be removed from your styles URL now.', 'secupress' ),
			5   => __( 'The WordPress version should be removed from your scripts URL now.', 'secupress' ),
			// warning
			100 => __( 'Unable to determine status of your homepage.', 'secupress' ),
			101 => sprintf( __( 'Unable to determine status of %s.', 'secupress' ), '<code>' . home_url( 'readme.html' ) . '</code>' ),
			// bad
			200 => __( 'The website displays the <strong>PHP version</strong> in the request headers.', 'secupress' ),
			201 => __( 'The website displays the <strong>WordPress version</strong> in the homepage source code (%s).', 'secupress' ),
			202 => sprintf( __( '<code>%s</code> should not be accessible by anyone.', 'secupress' ), home_url( 'readme.html' ) ),
			// cantfix
			/* translators: 1 is a file name, 2 is some code */
			300 => sprintf( __( 'Your server runs a nginx system, the PHP version disclosure in headers cannot be fixed automatically but you can do it yourself by adding the following code into your %1$s file: %2$s.', 'secupress' ), '<code>nginx.conf</code>', "<pre>$nginx_rules</pre>" ),
			301 => __( 'Your server runs a non recognized system. The PHP version disclosure in headers cannot be fixed automatically.', 'secupress' ),
			/* translators: 1 is a file name, 2 is some code */
			302 => __( 'Your %1$s file is not writable. Please add the following lines at the beginning of the file: %2$s.', 'secupress' ),
			303 => __( 'It seems URL rewriting is not enabled on your server. The sensitive information disclosure cannot be fixed.', 'secupress' ),
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	public function scan() {

		$wp_version   = get_bloginfo( 'version' );
		$php_version  = phpversion();
		$wp_discloses = array();

		// Get home page contents.
		$response     = wp_remote_get( user_trailingslashit( home_url() ), array( 'redirection' => 0 ) );
		$has_response = ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response );

		if ( $has_response ) {
			$powered_by = wp_remote_retrieve_header( $response, 'x-powered-by' );
			$body       = wp_remote_retrieve_body( $response );
		} else {
			// warning
			$this->add_message( 100 );
		}

		// Generator meta tag + php header
		if ( $has_response ) {

			// PHP version in headers.
			if ( false !== strpos( $powered_by, $php_version ) ) {
				// bad
				$this->add_message( 200 );
			}

			// WordPress version in meta tag.
			preg_match_all( '#<meta[^>]*[name="generator"]?[^>]*content="WordPress ' . $wp_version . '"[^>]*[name="generator"]?[^>]*>#si', $body, $matches );

			if ( count( array_filter( $matches ) ) ) {
				// bad
				$wp_discloses[] = 'META';
			}

		}

		// What about style tag src?
		$style_url = home_url( '/fake.css?ver=' . $wp_version );

		if ( $style_url === apply_filters( 'style_loader_src', $style_url, 'secupress' ) ) {
			// bad
			$wp_discloses[] = 'CSS';
		}

		// What about script tag src?
		$script_url = home_url( '/fake.js?ver=' . $wp_version );

		if ( $script_url === apply_filters( 'script_loader_src', $script_url, 'secupress' ) ) {
			// bad
			$wp_discloses[] = 'JS';
		}

		// Sum up!
		if ( $wp_discloses ) {
			// bad
			$this->add_message( 201, array( $wp_discloses ) );
		}

		// Readme file.
		$response = wp_remote_get( home_url( 'readme.html' ), array( 'redirection' => 0 ) );

		if ( ! is_wp_error( $response ) ) {

			if ( 200 === wp_remote_retrieve_response_code( $response ) ) {
				// bad
				$this->add_message( 202 );
			}

		} else {
			// warning
			$this->add_message( 101 );
		}

		// good
		$this->maybe_set_status( 0 );

		return parent::scan();
	}


	public function fix() {
		global $is_apache, $is_nginx, $is_iis7;

		$todo        = array();
		$wp_version  = get_bloginfo( 'version' );
		$php_version = phpversion();

		// Get home page contents.
		$response     = wp_remote_get( user_trailingslashit( home_url() ), array( 'redirection' => 0 ) );
		$has_response = ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response );

		// Generator meta tag + php header.
		if ( $has_response ) {

			$powered_by = wp_remote_retrieve_header( $response, 'x-powered-by' );
			$body       = wp_remote_retrieve_body( $response );

			// PHP version in headers.
			if ( false !== strpos( $powered_by, $php_version ) ) {
				$todo['php_version'] = 1;
			}

			// WordPress version in meta tag.
			preg_match_all( '#<meta[^>]*[name="generator"]?[^>]*content="WordPress ' . $wp_version . '"[^>]*[name="generator"]?[^>]*>#si', $body, $matches );

			if ( count( array_filter( $matches ) ) ) {
				// good
				secupress_activate_submodule( 'discloses', 'generator' );
				$this->add_fix_message( 3 );
			}

		} else {
			// warning
			$this->add_fix_message( 100 );
		}

		// What about style tag src?
		$style_url = home_url( '/fake.css?ver=' . $wp_version );

		if ( $style_url === apply_filters( 'style_loader_src', $style_url, 'secupress' ) ) {
			// good
			secupress_activate_submodule( 'discloses', 'wp-version-css' );
			$this->add_fix_message( 4 );
		}

		// What about script tag src?
		$script_url = home_url( '/fake.js?ver=' . $wp_version );

		if ( $script_url === apply_filters( 'script_loader_src', $script_url, 'secupress' ) ) {
			// good
			secupress_activate_submodule( 'discloses', 'wp-version-js' );
			$this->add_fix_message( 5 );
		}

		// Readme file.
		$response = wp_remote_get( home_url( 'readme.html' ), array( 'redirection' => 0 ) );

		if ( ! is_wp_error( $response ) ) {

			if ( 200 === wp_remote_retrieve_response_code( $response ) ) {
				$todo['readme'] = 1;
			}

		} else {
			// warning
			$this->add_fix_message( 101 );
		}

		if ( $todo ) {
			if ( $is_apache ) {
				$this->fix_apache( $todo );
			} elseif ( $is_iis7 ) {
				$this->fix_iis7( $todo );
			} elseif ( $is_nginx ) {
				$this->add_fix_message( 300 );
			} else {
				$this->add_fix_message( 301 );
			}
		}

		// good
		$this->maybe_set_fix_status( 0 );

		return parent::fix();
	}


	protected function fix_apache( $todo ) {
		$marker = 'versions_disclose';
		$rules  = '';

		// php version disclosure in header.
		if ( isset( $todo['php_version'] ) ) {
			$rules .= "ServerSignature Off\n";
			$rules .= "<IfModule mod_headers.c>\n    Header unset X-Powered-By\n</IfModule>\n";
		}

		// `readme.html` file.
		if ( isset( $todo['readme'] ) ) {
			if ( got_mod_rewrite() ) {
				$bases  = secupress_get_rewrite_bases();
				$base   = $bases['base'];
				$from   = $bases['home_from'];
				$rules .= "<IfModule mod_rewrite.c>\n";
				$rules .= "    RewriteEngine On\n";
				$rules .= "    RewriteBase $base\n";
				$rules .= "    RewriteRule ^{$from}(README|readme)\.(HTML|html)$ [R=404,L]\n"; // NC flag, why you no work?
				$rules .= "</IfModule>\n";
				$rules .= "<IfModule !mod_rewrite.c>\n";
				$rules .= "    <FilesMatch \"^(README|readme)\.(HTML|html)$\">\n";
				$rules .= "        deny from all\n";
				$rules .= "    </FilesMatch>\n";
				$rules .= "</IfModule>\n";
			} else {
				$rules .= "<FilesMatch \"^(README|readme)\.(HTML|html)$\">\n    deny from all\n</FilesMatch>\n";
			}
		}

		// Write in `.htaccess` file.
		if ( secupress_write_htaccess( $marker, $rules ) ) {
			// good
			$this->add_fix_message( 1, array( '<code>readme.html</code>', '<code>.htaccess</code>' ) );

			// Test our rule against php version disclosure works.
			$this->scan_php_disclosure();
		} else {
			// cantfix
			$this->add_fix_message( 302, array( '<code>.htaccess</code>', "<pre># BEGIN SecuPress $marker\n$rules# END SecuPress</pre>" ) );
		}
	}


	protected function fix_iis7() {
		if ( ! iis7_supports_permalinks() ) {
			// cantfix
			$this->add_fix_message( 303 );
			return;
		}

		$marker = 'versions_disclose';

		// php version disclosure in header.
		if ( isset( $todo['php_version'] ) ) {

			// https://www.iis.net/configreference/system.webserver/httpprotocol/customheaders
			// https://stackoverflow.com/questions/1178831/remove-server-response-header-iis7
			$spaces = str_repeat( ' ', 8 );

			$rules  = "<remove name=\"X-AspNet-Version\" id=\"SecuPress $marker 1\"/>\n";
			$rules .= "$spaces<remove name=\"X-AspNetMvc-Version\" id=\"SecuPress $marker 2\"/>\n";
			$rules .= "$spaces<remove name=\"X-Powered-By\" id=\"SecuPress $marker 3\"/>";

			$atts = array(
				'nodes_string' => $rules,
				'path'         => 'httpProtocol/customHeaders',
				'attribute'    => 'id',
			);

			// Write in `web.config` file.
			if ( secupress_insert_iis7_nodes( $marker, $atts ) ) {
				// good
				$this->add_fix_message( 1, array( '<code>web.config</code>' ) );

				// Test our rule against php version disclosure works.
				$this->scan_php_disclosure();

			} else {
				// cantfix
				$this->add_fix_message( 302, array( '<code>web.config</code>', "<pre>$rules</pre>" ) );
			}
		}

		// `readme.html` file.
		if ( isset( $todo['readme'] ) ) {

			$spaces = str_repeat( ' ', 10 );
			$bases  = secupress_get_rewrite_bases();
			$match  = '^' . $bases['home_from'] . 'readme\.html$';

			$rules  = "<rule name=\"SecuPress $marker\" stopProcessing=\"true\">\n";
			$rules .= "$spaces  <match url=\"$match\"/ ignoreCase=\"true\">\n";
			$rules .= "$spaces  <action type=\"CustomResponse\" statusCode=\"404\"/>\n";
			$rules .= "$spaces</rule>";

			// Write in `web.config` file.
			if ( secupress_insert_iis7_nodes( $marker, array( 'nodes_string' => $rules ) ) ) {
				// good
				$this->add_fix_message( 1, array( '<code>web.config</code>' ) );
			} else {
				// cantfix
				$this->add_fix_message( 302, array( '<code>web.config</code>', "<pre>{$spaces}{$rules}</pre>" ) );
			}
		}
	}


	protected function scan_php_disclosure() {
		global $is_apache;

		$response_test = wp_remote_get( user_trailingslashit( home_url() ), array( 'redirection' => 0 ) );

		if ( ! is_wp_error( $response_test ) && 200 === wp_remote_retrieve_response_code( $response_test ) ) {

			$powered_by  = wp_remote_retrieve_header( $response_test, 'x-powered-by' );
			$php_version = phpversion();

			if ( false !== strpos( $powered_by, $php_version ) ) {
				// good
				secupress_activate_submodule( 'discloses', 'php-version' );
				$file = '<code>' . ( $is_apache ? '.htaccess' : 'web.config' ) . '</code>';
				$this->add_fix_message( 2, array( $file ) );
			}
		}
	}
}
