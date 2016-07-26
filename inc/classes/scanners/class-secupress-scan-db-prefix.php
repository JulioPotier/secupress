<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * `DB Prefix` scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */
class SecuPress_Scan_DB_Prefix extends SecuPress_Scan implements SecuPress_Scan_Interface {

	/** Constants. ============================================================================== */

	/**
	 * Class version.
	 *
	 * @var (string)
	 */
	const VERSION = '1.0';


	/** Properties. ============================================================================= */

	/**
	 * The reference to the *Singleton* instance of this class.
	 *
	 * @var (object)
	 */
	protected static $_instance;


	/** Init and messages. ====================================================================== */

	/**
	 * Init.
	 *
	 * @since 1.0
	 */
	protected function init() {
		$this->title    = __( 'Check if your database prefix is correct.', 'secupress' );
		$this->more     = __( 'Avoid the usage of <code>wp_</code> or <code>wordpress_</code> as database prefix to improve your security.', 'secupress' );
		$this->more_fix = __( 'Rename all your database table names, then update your configuration with a new and more secure one.', 'secupress' );
	}


	/**
	 * Get messages.
	 *
	 * @since 1.0
	 *
	 * @param (int) $message_id A message ID.
	 *
	 * @return (string|array) A message if a message ID is provided. An array containing all messages otherwise.
	 */
	public static function get_messages( $message_id = null ) {
		$messages = array(
			// "good"
			0   => __( 'Your database prefix is correct.', 'secupress' ),
			// "bad"
			200 => __( 'The database prefix should not be %s. Choose something else than <code>wp_</code> or <code>wordpress_</code>, they are too easy to guess.', 'secupress' ),
			// "cantfix"
			301 => __( 'The database user can not alter tables and so the database prefix could not be changed.', 'secupress' ),
			302 => __( 'The <code>wp-config.php</code> file does not seem to be writable, so the database prefix cannot be changed.', 'secupress' ),
			303 => __( 'The database user seems to have to correct rights, but the database prefix could still not be changed.', 'secupress' ),
			304 => __( 'Too many database tables found, so which ones to rename?!', 'secupress' ), // Trinity! Help me!
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	/** Scan. =================================================================================== */

	/**
	 * Scan for flaw(s).
	 *
	 * @since 1.0
	 *
	 * @return (array) The scan results.
	 */
	public function scan() {
		global $wpdb;

		if ( get_transient( 'select-db-tables-to-rename' ) ) {
			$this->add_message( 100 );
		} else {
			// Check db prefix.
			$check = 'wp_' === $wpdb->prefix || 'wordpress_' === $wpdb->prefix;

			if ( $check ) {
				// "bad"
				$this->add_message( 200, array( '<code>' . $wpdb->prefix . '</code>' ) );
			}
		}
		// "good"
		$this->maybe_set_status( 0 );

		return parent::scan();
	}


	/** Fix. ==================================================================================== */

	/**
	 * Try to fix the flaw(s).
	 *
	 * @since 1.0
	 *
	 * @return (array) The fix results.
	 */
	public function fix() {
		// "good"
		$this->add_fix_message( 0 );

		return parent::fix();
	}


	/** Manual fix. ============================================================================= */

	/**
	 * Return an array of actions if a manual fix is needed here.
	 *
	 * @since 1.0
	 *
	 * @return (array)
	 */
	public function need_manual_fix() {
		global $wpdb;

		// Check db prefix.
		$check = 'wp_' === $wpdb->prefix || 'wordpress_' === $wpdb->prefix;

		if ( $check && secupress_db_access_granted() ) {

			$wpconfig_filename = secupress_find_wpconfig_path();

			if ( is_writable( $wpconfig_filename ) && preg_match( '/\$table_prefix.*=.*(\'' . $wpdb->prefix . '\'|"' . $wpdb->prefix . '");.*/', file_get_contents( $wpconfig_filename ) ) ) {

				$good_tables = secupress_get_non_wp_tables();

				if ( $good_tables ) {
					return array( 'select-db-tables-to-rename' => 'select-db-tables-to-rename' );
				}
			}
		}

		return array();
	}


	/**
	 * Try to fix the flaw(s) after requiring user action.
	 *
	 * @since 1.0
	 *
	 * @return (array) The fix results.
	 */
	public function manual_fix() {
		global $wpdb;

		if ( ! empty( $_POST ) && ! $this->has_fix_action_part( 'select-db-tables-to-rename' ) ) { // WPCS: CSRF ok.
			return parent::manual_fix();
		}

		$old_prefix   = $wpdb->prefix;
		$new_prefix   = secupress_create_unique_db_prefix();
		$query_tables = array();
		$good_tables  = secupress_get_non_wp_tables();
		$wp_tables    = secupress_get_wp_tables();

		if ( isset( $_POST['secupress-select-db-tables-to-rename-flag'] ) ) { // WPCS: CSRF ok.
			$good_tables = array_intersect( (array) $_POST['secupress-select-db-tables-to-rename'], $good_tables ); // WPCS: CSRF ok.
		}

		$good_tables = array_merge( $good_tables, $wp_tables );

		if ( is_multisite() ) {
			$blog_ids = $wpdb->get_col( "SELECT blog_id FROM {$wpdb->blogs} WHERE blog_id > 1" );

			if ( $blog_ids ) {
				foreach ( $blog_ids as $blog_id ) {
					foreach ( $wpdb->tables( 'blog' ) as $table ) {
						$table         = substr_replace( $table, $old_prefix . $blog_id . '_', 0, strlen( $old_prefix ) );
						$good_tables[] = $table;
					}
				}
			}
		}

		foreach ( $good_tables as $table ) {
			$new_table      = substr_replace( $table, $new_prefix, 0, strlen( $wpdb->prefix ) );
			$query_tables[] = "`{$table}` TO `{$new_table}`";
		}

		$wpdb->query( 'RENAME TABLE ' . implode( ', ', $query_tables ) ); // WPCS: unprepared SQL ok.

		if ( reset( $wpdb->get_col( "SHOW TABLES LIKE '{$new_prefix}options'" ) ) !== $new_prefix . 'options' ) { // WPCS: unprepared SQL ok.
			$this->add_fix_message( 303 );
		} else {
			secupress_replace_content( secupress_find_wpconfig_path(), '#\$table_prefix.*=.*(\'' . $old_prefix . '\'|"' . $old_prefix . '");.*#', '$table_prefix  = \'' . $new_prefix . '\'; // Modified by SecuPress' . "\n" . '/*Commented by SecuPress*/ // $0' );
			$old_prefix_len  = strlen( $old_prefix );
			$old_prefix_len1 = $old_prefix_len + 1;
			$wpdb->update( $new_prefix . 'options', array( 'option_name' => $new_prefix . 'user_roles' ), array( 'option_name' => $old_prefix . 'user_roles' ) );
			$wpdb->query( "UPDATE {$new_prefix}usermeta SET meta_key = CONCAT( REPLACE( LEFT( meta_key, {$old_prefix_len}), '$old_prefix', '$new_prefix' ), SUBSTR( meta_key, {$old_prefix_len1} ) )" ); // WPCS: unprepared SQL ok.

			if ( isset( $blog_ids ) && $blog_ids ) {
				foreach ( $blog_ids as $blog_id ) {
					$old_prefix_len  = strlen( $old_prefix ) + strlen( $blog_id ) + 1; // + 1 = "_"
					$old_prefix_len1 = $old_prefix_len + 1;
					$ms_prefix       = $new_prefix . $blog_id . '_';
					$wpdb->update( $ms_prefix . 'options', array( 'option_name' => $ms_prefix . 'user_roles' ), array( 'option_name' => $old_prefix . 'user_roles' ) );
					$wpdb->query( "UPDATE {$ms_prefix}usermeta SET meta_key = CONCAT( REPLACE( LEFT( meta_key, {$old_prefix_len}), '$old_prefix', '$ms_prefix' ), SUBSTR( meta_key, {$old_prefix_len1} ) )" ); // WPCS: unprepared SQL ok.
				}
			}

			$this->add_fix_message( 1, array( $new_prefix ) );
		}

		return parent::manual_fix();
	}


	/**
	 * Get an array containing ALL the forms that would fix the scan if it requires user action.
	 *
	 * @since 1.0
	 *
	 * @return (array) An array of HTML templates (form contents most of the time).
	 */
	protected function get_fix_action_template_parts() {
		global $wpdb;

		$good_tables = secupress_get_non_wp_tables();
		$wp_tables   = secupress_get_wp_tables();
		$blog_ids    = ! is_multisite() ? array( '1' ) : $wpdb->get_col( "SELECT blog_id FROM {$wpdb->blogs}" );

		$form  = '<div class="show-input">';
		$form .= '<h4>' . __( 'Check tables will be renamed:', 'secupress' ) . '</h4>';
		$form .= '<p><span style="color:red">' . __( 'Renaming a table is not rollbackable.', 'secupress' ) . '</span></p>';
		$form .= '<input type="hidden" name="secupress-select-db-tables-to-rename-flag">';
		$form .= '<fieldset aria-labelledby="select-db-tables-to-rename" class="secupress-boxed-group">';
		$form .= '<b>' . __( 'Unknown tables', 'secupress' ) . '</b><br>';
		foreach ( $good_tables as $table ) {
			$form .= '<input type="checkbox" name="secupress-select-db-tables-to-rename[]" value="' . $table . '" id="select-db-tables-to-rename-' . $table . '" checked="checked"><label for="select-db-tables-to-rename-' . $table . '">' . $table . '</label><br>';
		}
		$form .= '<b>' . __( 'WordPress tables (mandatory)', 'secupress' ) . '</b><br>';
		foreach ( $blog_ids as $blog_id ) {
			$blog_id = 1 === $blog_id ? '' : $blog_id . '_';

			foreach ( $wp_tables as $table ) {
				$table = substr_replace( $table, $wpdb->prefix . $blog_id, 0, strlen( $wpdb->prefix ) );
				$form .= '<input type="checkbox" id="secupress-select-db-tables-to-rename-' . $table . '" checked="checked" disabled="disabled"><label>' . $table . '</label><br>';
			}
		}
		$form .= '</fieldset>';
		$form .= '</div>';

		return array( 'select-db-tables-to-rename' => $form );
	}
}
