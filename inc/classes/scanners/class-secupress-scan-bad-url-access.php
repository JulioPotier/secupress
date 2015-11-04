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
		$messages = array(
			// good
			0   => __( 'Your site does not reveal sensitive informations.', 'secupress' ),
			1   => sprintf( __( 'Your %s file has been successfully edited.', 'secupress' ), '<code>.htaccess</code>' ),
			// warning
			100 => __( 'Unable to determine status of %s.', 'secupress' ),
			// bad
			200 => _n_noop( '%s should not be accessible by anyone.', '%s should not be accessible by anyone.', 'secupress' ),
			// cantfix
			300 => sprintf( __( 'You run a nginx system, I cannot fix these sensitive informations disclosures but you can do it yourself with the following code: %s.', 'secupress' ), '<code>(add nginx code here)</code>' ), ////
			301 => sprintf( __( 'You run an IIS7 system, I cannot fix these sensitive informations disclosures but you can do it yourself with the following code: %s.', 'secupress' ), '<code>(add IIS code here)</code>' ), //// iis7_url_rewrite_rules ?
			302 => __( 'You don\'t run an Apache system, I cannot fix these sensitive informations disclosures.', 'secupress' ),
			303 => __( 'Your %1$s file is not writable. Please add the following lines to the file: %2$s.', 'secupress' ),
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	public function scan() {

		// Avoid plugin's hooks of course.
		remove_all_filters( 'site_url' );
		remove_all_filters( 'admin_url' );
		remove_all_filters( 'home_url' );

		$urls = array(
			home_url( 'php.ini' ),
			admin_url( 'install.php' ),
			admin_url( 'menu.php' ),
			admin_url( 'menu-header.php' ),
			admin_url( 'includes/menu.php' ),
		);
		$bads     = array();
		$warnings = array();

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

		// Not Apache system, bail out.
		if ( ! $is_apache ) {

			if ( $is_nginx ) {
				$this->add_fix_message( 300 );
			} elseif ( $is_iis7 ) {
				$this->add_fix_message( 301 ); //// iis7_url_rewrite_rules
			} else {
				$this->add_fix_message( 302 );
			}

			return parent::fix();
		}

		// Edit `.htaccess` file.
		$base = parse_url( trailingslashit( get_option( 'home' ) ), PHP_URL_PATH );

		// Trigger a 404 error, because forbidding access to a file is nice, but making it also invisible is more fun :)
		$rules  = "<IfModule mod_rewrite.c>\n";
		$rules .= "    RewriteEngine On\n";
		$rules .= "    RewriteBase $base\n";
		$rules .= "    RewriteRule php.ini$ [R=404,L]\n";
		$rules .= "    RewriteRule wp-admin/install.php$ [R=404,L]\n";
		$rules .= "    RewriteRule wp-admin/menu.php$ [R=404,L]\n";
		$rules .= "    RewriteRule wp-admin/menu-header.php$ [R=404,L]\n";
		$rules .= "    RewriteRule wp-admin/setup-config.php$ [R=404,L]\n";
		$rules .= "    RewriteRule wp-admin/includes/menu.php$ [R=404,L]\n";
		$rules .= "</IfModule>\n";
		// But if rewrite is disabled, forbid access.
		$rules .= "<IfModule !mod_rewrite.c>\n";
		$rules .= "<FilesMatch \"^(php\.ini|install\.php|menu\.php|menu-header\.php\setup-config\.php)$\">\n";
		$rules .= "    deny from all\n";
		$rules .= "</FilesMatch>\n";
		$rules .= "</IfModule>";

		if ( secupress_write_htaccess( 'bad_url_access', $rules ) ) {
			// good
			$this->add_fix_message( 1, array( '<code>.htaccess</code>' ) );
		} else {
			// cantfix
			$this->add_fix_message( 303, array( '<code>.htaccess</code>', "<pre># BEGIN SecuPress bad_url_access\n$rules\n# END SecuPress</pre>" ) );
		}

		return parent::fix();
	}
}
