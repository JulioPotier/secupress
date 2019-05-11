<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * HTTPS scan class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Scan
 * @since 1.0
 */
class SecuPress_Scan_HTTPS extends SecuPress_Scan implements SecuPress_Scan_Interface {

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

	/**
	 * Tells if a scanner is fixable by SecuPress. The value "pro" means it's fixable only with the version PRO.
	 *
	 * @var (bool|string)
	 */
	protected $fixable = false;

	/** Init and messages. ====================================================================== */

	/**
	 * Init.
	 *
	 * @since 1.0
	 */
	protected function init() {
		$this->title    = __( 'Check if your website is using an active HTTPS connection.', 'secupress' );
		$this->more     = __( 'An HTTPS connection is needed for many features on the web today, it also gains the trust of your visitors by helping to protecting their online privacy.', 'secupress' );
		$this->more_fix = static::get_messages( 300 );
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
			0   => __( 'Your website is using an active HTTPS connection.', 'secupress' ),
			// "bad"
			200 => __( 'Only parts of your site are using HTTPS.', 'secupress' ),
			201 => __( 'Your site does not use HTTPS.', 'secupress' ),
			// "cantfix"
			300 => __( 'Cannot be fixed automatically. You have to contact you host provider to ask him to <strong>upgrade your site with HTTPS/SSL</strong>.', 'secupress' ),
		);

		if ( isset( $message_id ) ) {
			return isset( $messages[ $message_id ] ) ? $messages[ $message_id ] : __( 'Unknown message', 'secupress' );
		}

		return $messages;
	}


	/** Getters. ================================================================================ */

	/**
	 * Get the documentation URL.
	 *
	 * @since 1.2.3
	 *
	 * @return (string)
	 */
	public static function get_docs_url() {
		return __( 'http://docs.secupress.me/article/99-database-table-prefix-scan', 'secupress' ); ////
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

		$activated = secupress_filter_scanner( __CLASS__ );
		if ( true === $activated ) {
			$this->add_message( 0 );
			return parent::scan();
		}

		if ( is_ssl() ) {
			$wp_url   = get_bloginfo( 'wpurl' );
			$site_url = get_bloginfo( 'url' );

			if ( 'https' !== substr( $wp_url, 0, 5 ) || 'https' !== substr( $site_url, 0, 5 ) ) {
				// bad
				$this->add_message( 200 );
			}
		} else {
			// very bad
			$this->add_message( 201 );
		}
			// "good"
		$this->maybe_set_status( 0 );

		return parent::scan();
	}


	/** Fix. ==================================================================================== */

	/**
	 * Tell if we need to rename the table prefix.
	 *
	 * @since 1.1.1
	 * @author Grégory Viguier
	 *
	 * @return (bool)
	 */
	protected function need_fix() {
		$this->add_fix_message( 300 );
		return parent::fix();
	}


	/**
	 * Tell if the `wp-config.php` file can be fixed.
	 *
	 * @since 1.1.1
	 * @since 1.2.2 Returns the file path instead of true.
	 * @author Grégory Viguier
	 *
	 * @return (string|bool) The path of `wp-config.php` file or false.
	 */
	protected function is_wp_config_fixable() {
		global $wpdb;

		$wpconfig_filepath = secupress_is_wpconfig_writable();

		return $wpconfig_filepath && preg_match( '/\$table_prefix\s*=\s*(\'' . $wpdb->prefix . '\'|"' . $wpdb->prefix . '");.*/', file_get_contents( $wpconfig_filepath ) ) ? $wpconfig_filepath : false;
	}


	/**
	 * Try to fix the flaw(s).
	 *
	 * @since 1.0
	 *
	 * @return (array) The fix results.
	 */
	public function fix() {

		if ( ! $this->need_fix() ) {
			// "good"
			$this->add_fix_message( 0 );
			return parent::fix();
		}

		$can_fix = true;

		if ( ! secupress_db_access_granted() ) {
			// "cantfix"
			$this->add_fix_message( 301 );
			$can_fix = false;
		}

		if ( ! $this->is_wp_config_fixable() ) {
			// "cantfix"
			$this->add_fix_message( 302 );
			$can_fix = false;
		}

		if ( ! $can_fix ) {
			return parent::fix();
		}

		// "bad"
		$this->add_fix_message( 200 );

		return parent::fix();
	}


	/** Manual fix. ============================================================================= */

	/**
	 * Return an array of actions if a manual fix is needed here.
	 *
	 * @since 1.0
	 * @since 1.1.1 Return false instead of an empty array.
	 *
	 * @return (array|bool)
	 */
	public function need_manual_fix() {

		if ( ! $this->need_fix() ) {
			return false;
		}

		if ( ! $this->is_wp_config_fixable() ) {
			return false;
		}

		if ( ! secupress_db_access_granted() ) {
			return false;
		}

		// We have non WP table(s) to (maybe) rename, the user must choose.
		return array( 'select-db-tables-to-rename' => 'select-db-tables-to-rename' );
	}


	/**
	 * Try to fix the flaw(s) after requiring user action.
	 *
	 * @since 1.0
	 *
	 * @return (array) The fix results.
	 */
	public function manual_fix() {
		global $wpdb, $table_prefix;

		if ( ! empty( $_POST ) && ! $this->has_fix_action_part( 'select-db-tables-to-rename' ) ) { // WPCS: CSRF ok.
			return parent::manual_fix();
		}

		// Make the tests again, we want to be sure to not run this script unnecessarily.
		if ( ! $this->need_fix() ) {
			// "good"
			$this->add_fix_message( 0 );
			return parent::manual_fix();
		}

		$can_fix = true;

		if ( ! secupress_db_access_granted() ) {
			// "cantfix"
			$this->add_fix_message( 301 );
			$can_fix = false;
		}

		$wpconfig_filepath = $this->is_wp_config_fixable();

		if ( ! $wpconfig_filepath ) {
			// "cantfix"
			$this->add_fix_message( 302 );
			$can_fix = false;
		}

		if ( ! $can_fix ) {
			return parent::manual_fix();
		}

		// Let's start.
		$old_prefix       = $wpdb->prefix;
		$new_prefix       = secupress_create_unique_db_prefix();
		$query_tables     = array();
		$tables_to_rename = secupress_get_wp_tables();

		// Chosen non WP tables.
		if ( isset( $_POST['secupress-select-db-tables-to-rename-flag'] ) && ! empty( $_POST['secupress-select-db-tables-to-rename'] ) ) { // WPCS: CSRF ok.
			$non_wp_tables    = (array) $_POST['secupress-select-db-tables-to-rename']; // WPCS: CSRF ok.
			$non_wp_tables    = array_intersect( $non_wp_tables, secupress_get_non_wp_tables() );
			$tables_to_rename = array_merge( $non_wp_tables, $tables_to_rename );
		}

		// Tables for multisite.
		if ( is_multisite() ) {
			$blog_ids = $wpdb->get_col( "SELECT blog_id FROM {$wpdb->blogs} WHERE blog_id > 1" );

			if ( $blog_ids ) {
				foreach ( $blog_ids as $blog_id ) {
					$tables = $wpdb->tables( 'blog' );

					foreach ( $tables as $table ) {
						$tables_to_rename[] = substr_replace( $table, $old_prefix . $blog_id . '_', 0, strlen( $old_prefix ) );
					}
				}
			}
		}

		// Build the query to rename the tables.
		foreach ( $tables_to_rename as $table ) {
			$new_table      = substr_replace( $table, $new_prefix, 0, strlen( $wpdb->prefix ) );
			$query_tables[] = "`{$table}` TO `{$new_table}`";
		}

		$wpdb->query( 'RENAME TABLE ' . implode( ', ', $query_tables ) ); // WPCS: unprepared SQL ok.

		// Test if we succeeded.
		$options_tables = $wpdb->get_col( "SHOW TABLES LIKE '{$new_prefix}options'" ); // WPCS: unprepared SQL ok.

		if ( reset( $options_tables ) !== $new_prefix . 'options' ) { // WPCS: unprepared SQL ok.
			// Failed to rename the tables.
			$this->add_fix_message( 303 );
			return parent::manual_fix();
		}

		// We must not forget to change the prefix attribute for future queries.
		$table_prefix = $new_prefix; // WPCS: override ok.
		$wpdb->set_prefix( $table_prefix );

		// Some values must be updated.
		$old_prefix_len  = strlen( $old_prefix );
		$old_prefix_len1 = $old_prefix_len + 1;

		$wpdb->update( $new_prefix . 'options', array( 'option_name' => $new_prefix . 'user_roles' ), array( 'option_name' => $old_prefix . 'user_roles' ) );
		$wpdb->query( "UPDATE {$new_prefix}usermeta SET meta_key = CONCAT( REPLACE( LEFT( meta_key, {$old_prefix_len}), '$old_prefix', '$new_prefix' ), SUBSTR( meta_key, {$old_prefix_len1} ) )" ); // WPCS: unprepared SQL ok.

		if ( ! empty( $blog_ids ) ) {
			foreach ( $blog_ids as $blog_id ) {
				$old_prefix_len  = strlen( $old_prefix ) + strlen( $blog_id ) + 1; // + 1 = "_"
				$old_prefix_len1 = $old_prefix_len + 1;
				$ms_prefix       = $new_prefix . $blog_id . '_';

				$wpdb->update( $ms_prefix . 'options', array( 'option_name' => $ms_prefix . 'user_roles' ), array( 'option_name' => $old_prefix . 'user_roles' ) );
				$wpdb->query( "UPDATE {$ms_prefix}usermeta SET meta_key = CONCAT( REPLACE( LEFT( meta_key, {$old_prefix_len}), '$old_prefix', '$ms_prefix' ), SUBSTR( meta_key, {$old_prefix_len1} ) )" ); // WPCS: unprepared SQL ok.
			}
		}

		// `wp-config.php` file.
		secupress_replace_content(
			$wpconfig_filepath,
			'@^[\t ]*?\$table_prefix\s*=\s*(?:\'' . $old_prefix . '\'|"' . $old_prefix . '")\s*;.*?$@mU',
			'$table_prefix = \'' . $new_prefix . "'; // Modified by SecuPress.\n/** Commented by SecuPress. */ // $0"
		);

		$this->add_fix_message( 0 );

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

		$non_wp_tables = secupress_get_non_wp_tables();
		$wp_tables     = secupress_get_wp_tables();
		$blog_ids      = ! is_multisite() ? array( '1' ) : $wpdb->get_col( "SELECT blog_id FROM {$wpdb->blogs}" );

		$form  = '<div class="show-input">';

		$form .= '<h4>' . __( 'Checked tables will be renamed:', 'secupress' ) . '</h4>';
		$form .= '<p><span style="color:red">' . __( 'Renaming a table is irreversible.', 'secupress' ) . '</span></p>';
		$form .= '<input type="hidden" name="secupress-select-db-tables-to-rename-flag">';

		$form .= '<fieldset aria-labelledby="select-db-tables-to-rename" class="secupress-boxed-group">';

		$form .= '<b>' . __( 'Unknown tables', 'secupress' ) . '</b><br/>';

		if ( $non_wp_tables ) {
			foreach ( $non_wp_tables as $table ) {
				$table_attr = esc_attr( $table );
				$form      .= '<input type="checkbox" name="secupress-select-db-tables-to-rename[]" value="' . $table_attr . '" id="select-db-tables-to-rename-' . $table_attr . '" checked="checked"><label for="select-db-tables-to-rename-' . $table_attr . '">' . esc_html( $table ) . '</label><br/>';
			}
		} else {
			$form .= '<em>' . _x( 'None', 'database table', 'secupress' ) . '</em><br/>';
		}

		$form .= '<b>' . __( 'WordPress tables (mandatory)', 'secupress' ) . '</b><br/>';

		foreach ( $blog_ids as $blog_id ) {
			$blog_id = '1' === $blog_id ? '' : $blog_id . '_';

			foreach ( $wp_tables as $table ) {
				$table = substr_replace( $table, $wpdb->prefix . $blog_id, 0, strlen( $wpdb->prefix ) );
				$form .= '<input type="checkbox" id="secupress-select-db-tables-to-rename-' . esc_attr( $table ) . '" checked="checked" disabled="disabled"><label>' . esc_html( $table ) . '</label><br/>';
			}
		}

		$form .= '</fieldset>';

		$form .= '</div>';

		return array( 'select-db-tables-to-rename' => $form );
	}
}
