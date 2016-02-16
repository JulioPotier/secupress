<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * readme.txt disclose scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */

class SecuPress_Scan_Readme_Discloses extends SecuPress_Scan implements iSecuPress_Scan {

	const VERSION = '1.0';

	/**
	 * @var Singleton The reference to *Singleton* instance of this class
	 */
	protected static $_instance;
	public    static $prio = 'medium';


	protected static function init() {
		self::$type  = __( 'Plugins and Themes', 'secupress' );
		/* translators: %s is a file name */
		self::$title = sprintf( __( 'Check if the %s files from your plugins and themes are protected.', 'secupress' ), '<code>readme.txt</code>' );
		self::$more  = __( 'When an attacker wants to hack into a WordPress site, he will search for a maximum of informations. His goal is to find outdated versions of your server softwares or WordPress components. Don\'t let them easily find these informations.', 'secupress' );
	}


	public static function get_messages( $message_id = null ) {
		global $is_nginx;

		$nginx_rules = '';

		if ( $is_nginx ) {
			$base         = secupress_get_rewrite_bases();
			$base         = rtrim( $bases['home_from'], '/' );
			$marker       = 'readme_discloses';
			$pattern      = '(readme|changelog)\.(txt|md|html)$';
			// http://nginx.org/en/docs/http/ngx_http_core_module.html#location
			$nginx_rules .= "server {\n\t# BEGIN SecuPress $marker\n";
				$nginx_rules .= "\tlocation ~* ^$base(/|/.+/)$pattern {\n\t\treturn 404;\n\t}\n";
			$nginx_rules .= "\t# END SecuPress\n}";
		}

		$messages = array(
			// good
			/* translators: %s is a file name */
			0   => sprintf( __( 'The %s files from your plugins and themes are protected.', 'secupress' ), '<code>readme.txt</code>' ),
			/* translators: 1 and 2 are file names */
			1   => sprintf( __( 'The rules forbidding access to your %1$s files have been successfully added to your %2$s file.', 'secupress' ), '<code>readme.txt</code>', '%s' ),
			// warning
			/* translators: %s is a file name */
			100 => sprintf( __( 'Unable to determine status of the %s files.', 'secupress' ), '<code>readme.txt</code>' ),
			// bad
			/* translators: %s is a file name */
			200 => sprintf( __( 'The %s files from your plugins and themes are accessible to anyone.', 'secupress' ), '<code>readme.txt</code>' ),
			// cantfix
			/* translators: 1 and 2 are file names, 2 is some code */
			300 => sprintf( __( 'Your server runs a nginx system, the %1$s files from your plugins and themes cannot be protected automatically but you can do it yourself by adding the following code into your %1$s file: %2$s.', 'secupress' ), '<code>readme.txt</code>', '<code>nginx.conf</code>', "<pre>$nginx_rules</pre>" ),
			/* translators: %s is a file name */
			301 => sprintf( __( 'Your server runs a non recognized system. The %s files from your plugins and themes cannot be protected automatically.', 'secupress' ), '<code>readme.txt</code>' ),
			/* translators: 1 is a file name, 2 is some code */
			302 => __( 'Your %1$s file is not writable. Please add the following lines at the beginning of the file: %2$s.', 'secupress' ),
			/* translators: %s is a file name */
			303 => sprintf( __( 'It seems URL rewriting is not enabled on your server. The %s files from your plugins and themes cannot be protected.', 'secupress' ), '<code>readme.txt</code>' ),
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	public function scan() {
		$protected = static::_are_files_protected();

		if ( is_null( $protected ) ) {
			// warning
			$this->add_message( 100 );

		} elseif ( $protected ) {
			// good
			$this->add_message( 0 );

		} else {
			// bad
			$this->add_message( 200 );
		}

		return parent::scan();
	}


	public function fix() {
		global $is_apache, $is_nginx, $is_iis7;

		$protected = static::_are_files_protected();

		if ( is_null( $protected ) ) {
			// warning
			$this->add_fix_message( 100 );
			return parent::fix();
		}

		if ( $protected ) {
			// good
			$this->add_fix_message( 0 );
			return parent::fix();
		}

		if ( $is_apache ) {
			$this->_fix_apache();
		} elseif ( $is_iis7 ) {
			$this->_fix_iis7();
		} elseif ( $is_nginx ) {
			$this->add_fix_message( 300 );
		} else {
			$this->add_fix_message( 301 );
		}

		// good
		$this->maybe_set_fix_status( 0 );

		return parent::fix();
	}


	protected function _fix_apache() {
		$marker  = 'readme_discloses';
		$pattern = '(README|CHANGELOG|readme|changelog)\.(TXT|MD|HTML|txt|md|html)$';

		if ( got_mod_rewrite() ) {
			$rules  = "<IfModule mod_rewrite.c>\n";
			$rules .= "    RewriteEngine On\n";
			$rules .= "    RewriteRule /$pattern [R=404,L]\n"; // NC flag, why you no work?
			$rules .= "</IfModule>\n";
			$rules .= "<IfModule !mod_rewrite.c>\n";
			$rules .= "    <FilesMatch \"^$pattern\">\n";
			$rules .= "        deny from all\n";
			$rules .= "    </FilesMatch>\n";
			$rules .= "</IfModule>\n";
		} else {
			$rules  = "<FilesMatch \"^$pattern\">\n    deny from all\n</FilesMatch>\n";
		}

		// Write in `.htaccess` file.
		if ( secupress_write_htaccess( $marker, $rules ) ) {
			// good
			$this->add_fix_message( 1, array( '<code>.htaccess</code>' ) );
		} else {
			// cantfix
			$this->add_fix_message( 302, array( '<code>.htaccess</code>', "<pre># BEGIN SecuPress $marker\n$rules# END SecuPress</pre>" ) );
		}
	}


	protected function _fix_iis7() {
		if ( ! iis7_supports_permalinks() ) {
			// cantfix
			$this->add_fix_message( 303 );
			return;
		}

		$marker = 'readme_discloses';
		$spaces = str_repeat( ' ', 10 );
		$bases  = secupress_get_rewrite_bases();
		$match  = '^' . $bases['home_from'] . '.*/(readme|changelog)\.(txt|md|html)$';

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


	protected static function _are_files_protected() {
		// Get all readme/changelog files.
		$plugins = rtrim( secupress_get_plugins_path(), '\\/' );
		$themes  = rtrim( secupress_get_themes_path(), '\\/' );
		$pattern = '{' . $plugins . ',' . $themes . '}/*/{README,CHANGELOG,readme,changelog}.{TXT,MD,HTML,txt,md,html}';
		$files   = glob( $pattern, GLOB_BRACE );

		// No file? Good, nothing to protect.
		if ( ! $files ) {
			// good.
			return true;
		}

		// Get the first file path, relative to the root of the site.
		$abspath = wp_normalize_path( ABSPATH );
		$file    = reset( $files );
		$file    = wp_normalize_path( $file );
		$file    = ltrim( str_replace( $abspath, '', $file ), '/' );

		// Get file contents.
		$response = wp_remote_get( site_url( $file ), array( 'redirection' => 0 ) );

		if ( is_wp_error( $response ) ) {
			// warning.
			return null;
		} elseif ( 200 === wp_remote_retrieve_response_code( $response ) ) {
			// bad.
			return false;
		}
		// good.
		return true;
	}
}
