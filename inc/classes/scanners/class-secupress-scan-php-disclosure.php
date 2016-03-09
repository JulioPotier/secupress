<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * PHP Disclosure scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */

class SecuPress_Scan_PHP_Disclosure extends SecuPress_Scan implements iSecuPress_Scan {

	const VERSION = '1.0';

	/**
	 * @var Singleton The reference to *Singleton* instance of this class
	 */
	protected static $_instance;
	public    static $prio = 'low';


	protected static function init() {
		global $is_apache, $is_nginx, $is_iis7;

		self::$type  = 'WordPress';
		self::$title = __( 'Check if your WordPress site discloses the PHP modules <em>(know as PHP Easter Egg)</em>.', 'secupress' );
		self::$more  = __( 'PHP contains a flaw that may lead to an unauthorized information disclosure. The issue is triggered when a remote attacker makes certain HTTP requests with crafted arguments, which will disclose PHP version and another sensitive information resulting in a loss of confidentiality.', 'secupress' );

		$config_file = '';
		if ( $is_apache ) {
			$config_file = '.htaccess';
		} elseif( $is_iis7 ) {
			$config_file = 'web.config';
		} elseif( $is_nginx ) {
			$config_file = 'nginx.conf';
		}
		if ( $config_file ) {
			self::$more_fix = sprintf( __( 'The fix will add rules in your %s file to avoid attackers to read sentitive informations from your installation,', 'secupress' ), '<code>' . $config_file . '</code>' );
		} else {
			self::$more_fix = __( 'Your server runs a non recognized system. This cannot be fixed automatically.', 'secupress' );
		}
	}


	public static function get_messages( $message_id = null ) {
		$marker      = 'php_disclosure';
		$nginx_rules = "location / {\n\t\t" . 'if ( $query_string ~* "\=PHP[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}" ) {' . "\n\t\t\treturn 403;\n\t\t}\n\t}";
		$nginx_rules = "server {\n\t# BEGIN SecuPress $marker\n\t$nginx_rules\n\t# END SecuPress\n}";

		$messages = array(
			// good
			0   => __( 'Your site does not reveal the PHP modules.', 'secupress' ),
			1   => sprintf( __( 'Your %s file has been successfully edited.', 'secupress' ), '<code>.htaccess</code>' ),
			// warning
			100 => sprintf( __( 'Unable to determine status of %s.', 'secupress' ), '<code>' . user_trailingslashit( home_url() ) . '?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000</code>' ),
			// bad
			200 => sprintf( __( '%s should not be accessible to anyone.', 'secupress' ), '<code>' . user_trailingslashit( home_url() ) . '?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000</code>' ),
			// cantfix
			/* translators: 1 is a block name, 2 is a file name, 3 is some code */
			300 => sprintf( __( 'Your server runs a nginx system, the sensitive information disclosure cannot be fixed automatically but you can do it yourself by adding the following code inside the %1$s block of your %2$s file: %3$s.', 'secupress' ), '"server"', '<code>nginx.conf</code>', "<pre>$nginx_rules</pre>" ),
			301 => __( 'Your server runs a non recognized system. The sensitive information disclosure cannot be fixed automatically.', 'secupress' ),
			/* translators: 1 si a file name, 2 is some code */
			302 => __( 'Your %1$s file is not writable. Please add the following lines at the beginning of the file: %2$s.', 'secupress' ),
			303 => __( 'It seems URL rewriting is not enabled on your server. The sensitive information disclosure cannot be fixed.', 'secupress' ),
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	public function scan() {

		// http://osvdb.org/12184
		$response = wp_remote_get( user_trailingslashit( home_url() ) . '?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000', array( 'redirection' => 0 ) );

		if ( ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response ) ) {

			$body = wp_remote_retrieve_body( $response );

			if ( strpos( $body, '<h1>PHP Credits</h1>' ) > 0 && strpos( $body, '<title>phpinfo()</title>' ) > 0 ) {
				// bad
				$this->add_message( 200 );
			}

		} elseif ( is_wp_error( $response ) ) {
			// warning
			$this->add_message( 100 );
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
		$marker = 'php_disclosure';
		$rules  = "<IfModule mod_rewrite.c>\n";
		$rules .= "    RewriteEngine on\n";
		$rules .= "    RewriteCond %{QUERY_STRING} \=PHP[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12} [NC]\n";
		$rules .= "    RewriteRule .* - [F]\n";
		$rules .= "</IfModule>";

		if ( ! got_mod_rewrite() ) {
			// cantfix
			$this->add_fix_message( 303 );
		} elseif ( secupress_write_htaccess( $marker, $rules ) ) {
			// good
			$this->add_fix_message( 1, array( '<code>.htaccess</code>' ) );
		} else {
			// cantfix
			$this->add_fix_message( 302, array( '<code>.htaccess</code>', "<pre># BEGIN SecuPress $marker\n$rules\n# END SecuPress</pre>" ) );
		}
	}


	protected function fix_iis7() {
		$marker = 'php_disclosure';
		$spaces = str_repeat( ' ', 10 );
		$node   = "<rule name=\"SecuPress $marker\" stopProcessing=\"true\">\n";
			$node  .= "$spaces  <match url=\".*\"/>\n";
			$node  .= "$spaces  <conditions>\n";
				$node  .= "$spaces    <add input=\"{URL}\" pattern=\"\=PHP[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\" ignoreCase=\"true\"/>\n";
			$node  .= "$spaces  </conditions>\n";
			$node  .= "$spaces  <action type=\"AbortRequest\"/>\n";
		$node  .= "$spaces</rule>";

		if ( ! iis7_supports_permalinks() ) {
			// cantfix
			$this->add_fix_message( 303 );
		} elseif ( secupress_insert_iis7_nodes( $marker, array( 'nodes_string' => $node ) ) ) {
			// good
			$this->add_fix_message( 1, array( '<code>web.config</code>' ) );
		} else {
			// cantfix
			$this->add_fix_message( 302, array( '<code>web.config</code>', '<pre>' . $node . '</pre>' ) );
		}
	}
}
