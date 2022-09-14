<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/**
 * DB Prefix scan class.
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
	const VERSION = '1.0.2';


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
	protected $fixable = 'pro';

	/** Init and messages. ====================================================================== */

	/**
	 * Init.
	 *
	 * @since 1.0
	 */
	protected function init() {
		$this->title    = __( 'Check if your database tables prefix is correct.', 'secupress' );
		$this->more     = __( 'Avoid the use of <code>wp_</code> or <code>wordpress_</code> as database tables prefix to improve your security.', 'secupress' );
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
			0   => __( 'Your database tables prefix is correct.', 'secupress' ),
			// "bad"
			200 => __( 'The database tables prefix should not be %s. Choose something else besides <code>wp_</code> or <code>wordpress_</code>, they are too easy to guess.', 'secupress' ),
			// "cantfix"
			301 => __( 'The database user cannot alter tables and so the database tables prefix could not be changed.', 'secupress' ),
			302 => sprintf( __( 'The <code>%s</code> file is not writable, so the database tables prefix cannot be changed.', 'secupress' ), secupress_get_wpconfig_filename( 'db' ) ),
			303 => __( 'The database user seems to have to correct rights, but the database tables prefix could still not be changed.', 'secupress' ),
			304 => __( 'Too many database tables found, so which ones to rename?!', 'secupress' ), // Trinity! Help me!
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
		return __( 'https://docs.secupress.me/article/99-database-table-prefix-scan', 'secupress' );
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

		$activated = $this->filter_scanner( __CLASS__ );
		if ( true === $activated ) {
			$this->add_message( 0 );
			return parent::scan();
		}

		global $wpdb;

		if ( $this->need_fix() ) {
			// "bad"
			$this->add_message( 200, array( '<code>' . $wpdb->prefix . '</code>' ) );
		} else {
			// "good"
			$this->add_message( 0 );
		}

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
		global $wpdb;
		return 'wp_' === $wpdb->prefix || 'wordpress_' === $wpdb->prefix;
	}


	/**
	 * Tell if the `wp-config.php` file can be fixed.
	 *
	 * @since 1.2.2 Returns the file path instead of true.
	 * @since 1.1.1
	 * @author Grégory Viguier
	 *
	 * @return (string|bool) The path of `wp-config.php` file or false.
	 */
	protected function is_wp_config_fixable() {
		global $wpdb;

		$wpconfig_filepath = secupress_is_wpconfig_writable( 'db' );

		if ( ! $wpconfig_filepath ) {
			return false;
		}

		// Get the file content
		$file_content = file_get_contents( $wpconfig_filepath );
		// Find the string we need with WP default syntax
		$match_default = preg_match( '/\$table_prefix\s*=\s*(\'' . $wpdb->prefix . '\'|"' . $wpdb->prefix . '");.*/', $file_content );
		if ( $match_default ) {
			return $wpconfig_filepath;
		}

		// Find the string we need with GLOBALS syntax
		$match_globals = preg_match( '/\$GLOBALS[\'table_prefix\']\s*=\s*(\'' . $wpdb->prefix . '\'|"' . $wpdb->prefix . '");.*/', $file_content );
		if ( $match_globals ) {
			return $wpconfig_filepath;
		}

		// Nothing found
		return false;
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

		if ( ! secupress_where_is_table_prefix() ) {
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

		if ( ! secupress_where_is_table_prefix() ) {
			return false;
		}

		if ( ! secupress_db_access_granted() ) {
			return array( 'db_access' => 'db_access' );
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

		$wpconfig_filepath = secupress_where_is_table_prefix();

		if ( ! $wpconfig_filepath ) {
			// "cantfix"
			$this->add_fix_message( 302 );
			$can_fix = false;
		}

		if ( ! $can_fix ) {
			return parent::manual_fix();
		}

		// Chosen non WP tables.
		$tables_to_rename = secupress_get_wp_tables();
		if ( isset( $_POST['secupress-select-db-tables-to-rename-flag'] ) && ! empty( $_POST['secupress-select-db-tables-to-rename'] ) ) { // WPCS: CSRF ok.
			$non_wp_tables    = (array) $_POST['secupress-select-db-tables-to-rename']; // WPCS: CSRF ok.
			$non_wp_tables    = array_intersect( $non_wp_tables, secupress_get_non_wp_tables() );
			$tables_to_rename = array_merge( $non_wp_tables, $tables_to_rename );
		}
		secupress_change_db_prefix( secupress_create_unique_db_prefix(), $tables_to_rename );

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
		$form .= '<input type="hidden" name="secupress-select-db-tables-to-rename-flag">';

		$form .= '<fieldset aria-labelledby="select-db-tables-to-rename" class="secupress-boxed-group">';


		if ( $non_wp_tables ) {
			$form .= '<b>' . __( 'Unknown tables', 'secupress' ) . '</b><br/>';
			foreach ( $non_wp_tables as $table ) {
				$table_attr = esc_attr( $table );
				$form      .= '<input type="checkbox" name="secupress-select-db-tables-to-rename[]" value="' . $table_attr . '" id="select-db-tables-to-rename-' . $table_attr . '" checked="checked"><label for="select-db-tables-to-rename-' . $table_attr . '">' . esc_html( $table ) . '</label><br/>';
			}
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

		return [ 'select-db-tables-to-rename' => $form,
				 'db_access' => $this->get_messages( 301 ) . '<br>' . sprintf( __( 'Please <a href="%s">read the documentation</a>.', 'secupress' ), $this->get_docs_url() ),
				 'wpconfig_fixable' => $this->get_messages( 302 ) . '<br>' . sprintf( __( 'Please <a href="%s">read the documentation</a>.', 'secupress' ), $this->get_docs_url() ),
			 	];
	}
}
