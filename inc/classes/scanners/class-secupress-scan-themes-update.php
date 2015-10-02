<?php
defined( 'ABSPATH' ) or die('Cheatin\' uh?');

/**
 * Themes Update scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */

class SecuPress_Scan_Themes_Update extends SecuPress_Scan implements iSecuPress_Scan {

	const VERSION = '1.0';

	/**
	 * @var Singleton The reference to *Singleton* instance of this class
	 */
	protected static $_instance;
	public    static $prio = 'high';


	protected static function init() {
		self::$type    = 'WordPress';
		self::$title   = __( 'Check if your themes are up to date.', 'secupress' );
		self::$more    = __( 'It\'s very important to maintain your WordPress installation up to date. If you can not update because of a theme, contact its author and submit your issue.', 'secupress' );
	}


	public static function get_messages( $message_id = null ) {
		$messages = array(
			// good
			0   => __( 'Your themes are up to date.', 'secupress' ),
			// bad
			200 => _n_noop( '<strong>%1$d</strong> theme isn\'t up to date: %2$s.',  '<strong>%1$d</strong> themes aren\'t up to date: %2$s.', 'secupress' ),
			// cantfix
			300 => __( 'I can not fix this, you have to manually update your plugins, themes and WordPress core.', 'secupress' ),
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	public function scan() {
		ob_start();

		// Themes
		wp_update_themes();
		$current       = get_site_transient( 'update_themes' );
		$theme_updates = array();

		if ( isset( $current->response ) && is_array( $current->response ) ) {
			$theme_updates = wp_list_pluck( array_map( 'wp_get_theme', array_keys( $current->response ) ), 'Name' );
		}

		ob_flush();

		if ( $count = count( $theme_updates ) ) {
			// bad
			$this->add_message( 200, array( $count, $count, wp_sprintf_l( '%l', self::wrap_in_tag( $theme_updates ) ) ) );
		}

		// good
		$this->maybe_set_status( 0 );

		return parent::scan();
	}


	public function fix() {

		ob_start();
		@set_time_limit( 0 );

		// Themes
		$themes = get_site_transient( 'update_themes' );
		$themes = isset( $themes->response ) ? array_keys( $themes->response ) : false;
		if ( $themes ) {
			$url = 'update.php?action=update-selected-themes&amp;themes=' . urlencode( implode( ',', $themes ) );
			$nonce = 'bulk-update-themes';
			include_once( ABSPATH . 'wp-admin/includes/class-wp-upgrader.php' );
			$skin = new Automatic_Upgrader_Skin( compact( 'nonce', 'url' ) );
			$upgrader = new Theme_Upgrader( $skin );
			$upgrader->bulk_upgrade( $themes ); 	
		}	

		ob_end_clean();

		return parent::fix();
	}
}
