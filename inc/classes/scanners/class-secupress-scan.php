<?php
defined( 'ABSPATH' ) or die('Cheatin\' uh?');


/**
 * Base scan interface.
 *
 * @package SecuPress
 * @since 1.0
 */

interface iSecuPress_Scan {

	public static function get_messages( $message_id = null );
	public function scan();
	public function fix();

}


/**
 * Base scan abstract class.
 *
 * @package SecuPress
 * @since 1.0
 */

abstract class SecuPress_Scan extends SecuPress_Singleton implements iSecuPress_Scan {

	const VERSION = '1.0';

	// Filled when fixes need manual actions.
	private       $fix_actions = array();

	// The part of the class that extends this one, like SecuPress_Scan_{$class_name_part}.
	protected     $class_name_part;
	// Contain scan results.
	protected     $result     = array();
	// Contain fix results.
	protected     $result_fix = array();
	/*
	 * On multisite, some fixes can't be performed from the network admin.
	 * This array will contain a list of site IDs with scan messages.
	 */
	protected     $fix_sites;
	/*
	 * On multisite, if `$for_current_site` is true, then the scan/fix/etc are performed for the current site, not wetwork-widely.
	 * If needed, should be set right after instanciation.
	 * Does nothing on non-multisite installations.
	 */
	protected     $for_current_site = false;

	public static $prio    = '';
	public static $type    = '';
	public static $title   = '';
	public static $more    = '';
	public static $fixable = true;


	// Init ========================================================================================

	/**
	 * Init: this method is required by the class `SecuPress_Singleton`.
	 *
	 * @since 1.0
	 */
	protected function _init() {
		$this->class_name_part = substr( get_called_class(), 15 ); // 15 is 'SecuPress_Scan_' length.
		static::init();
	}


	/**
	 * Sub-classes init.
	 *
	 * @since 1.0
	 */
	protected static function init() {
		die( 'Method SecuPress_Scan::init() must be over-ridden in a sub-class.' );
	}


	// Multisite specifics =========================================================================

	// Get `$for_current_site`.

	final public function is_for_current_site() {
		return $this->for_current_site;
	}


	// `is_network_admin()` does not work in an ajax callback.

	final public function is_network_admin() {
		return is_multisite() && ! $this->is_for_current_site();
	}


	// Set `$for_current_site`.

	final public function for_current_site( $for_current_site = null ) {
		$this->for_current_site = (bool) $for_current_site;
		return $this;
	}


	// Messages for scans and fixes ================================================================

	// Get messages.

	public static function get_messages( $message_id = null ) {
		die( 'Method SecuPress_Scan::get_messages() must be over-ridden in a sub-class.' );
	}


	// Status and messages for scans ===============================================================

	// Maybe set current scan status.

	final protected function set_status( $status, $force = false ) {
		$statuses = array(
			'cantfix' => 0,
			'good'    => 1,
			'warning' => 2,
			'bad'     => 3,
		);

		if ( $this->is_for_current_site() ) {
			return $this->set_subsite_status( $status, 'scan', 0, $force );
		}

		// Unkown status
		if ( ! isset( $statuses[ $status ] ) ) {
			return false;
		}

		// No previous status
		if ( empty( $this->result['status'] ) || $force ) {
			$this->result['status'] = $status;
			return $status;
		}

		// Status already set: only allow to "upgrade" to a superior status.
		if ( $statuses[ $status ] > $statuses[ $this->result['status'] ] ) {
			$this->result['status'] = $status;
		}

		return $this->result['status'];
	}


	/*
	 * Add a scan message and automatically set the scan status.
	 *
	 * good:    the scan performed correctly and returned a good result.
	 * warning: the scan could not perform correctly.
	 * bad:     the scan performed correctly but returned a bad result.
	 */

	final protected function add_message( $message_id, $params = array() ) {
		if ( $this->is_for_current_site() ) {
			return $this->add_subsite_message( $message_id, $params );
		}

		$this->result['msgs'] = isset( $this->result['msgs'] ) ? $this->result['msgs'] : array();
		$this->result['msgs'][ $message_id ] = $params;
		$this->set_status( static::get_status_from_message_id( $message_id ) );
	}


	// Are scan status and message(s) set?

	final protected function has_status() {
		if ( $this->is_for_current_site() ) {
			return $this->has_subsite_status();
		}

		return ! empty( $this->result );
	}


	// Set a scan status + message only if no status is set yet.

	final protected function maybe_set_status( $message_id, $params = array() ) {
		if ( $this->is_for_current_site() ) {
			return $this->maybe_set_subsite_status( $message_id, $params );
		}

		if ( ! $this->has_status() ) {
			$this->add_message( $message_id, $params );
		}
	}


	// Status and messages for fixes ===============================================================

	// Maybe set current fix status.

	final protected function set_fix_status( $status, $force = false ) {
		$statuses = array(
			'cantfix' => 0,
			'good'    => 1,
			'warning' => 2,
			'bad'     => 3,
		);

		if ( $this->is_for_current_site() ) {
			return $this->set_subsite_status( $status, 'fix', 0, $force );
		}

		// Unkown status
		if ( ! isset( $statuses[ $status ] ) ) {
			return false;
		}

		// No previous status
		if ( empty( $this->result_fix['status'] ) || $force ) {
			$this->result_fix['status'] = $status;
			return $status;
		}

		// Status already set: only allow to "upgrade" to a superior status.
		if ( $statuses[ $status ] > $statuses[ $this->result_fix['status'] ] ) {
			$this->result_fix['status'] = $status;
		}

		return $this->result_fix['status'];
	}


	/*
	 * Add a fix message and automatically set the fix status.
	 *
	 * good:    the fix performed correctly.
	 * warning: partial fix. The fix could not perform entirely: some fix(es) worked and some not.
	 * bad:     error. The fix could not perform correctly.
	 * cantfix: neutral. The flaw cannot be fixed by this plugin.
	 */

	public function add_fix_message( $message_id, $params = array() ) {
		if ( $this->is_for_current_site() ) {
			return $this->add_subsite_message( $message_id, $params, 'fix' );
		}

		$this->result_fix['msgs'] = isset( $this->result_fix['msgs'] ) ? $this->result_fix['msgs'] : array();
		$this->result_fix['msgs'][ $message_id ] = $params;
		$this->set_fix_status( static::get_status_from_message_id( $message_id ) );
	}


	// Are fix status and message(s) set?

	final protected function has_fix_status() {
		if ( $this->is_for_current_site( 'fix' ) ) {
			return $this->has_subsite_status( 'fix' );
		}

		return ! empty( $this->result_fix );
	}


	// Set a fix status + message only if no status is set yet.

	final protected function maybe_set_fix_status( $message_id, $params = array() ) {
		if ( $this->is_for_current_site() ) {
			return $this->maybe_set_subsite_status( $message_id, $params, 'fix' );
		}

		if ( ! $this->has_fix_status() ) {
			$this->add_fix_message( $message_id, $params );
		}
	}


	// Messages for subsites =======================================================================

	/*
	 * On multisite, some fixes can't be performed from the network admin.
	 * Here we store a list of site IDs with some data:
	 * array(
	 *    blog_id => array(
	 *        'scan' => array(
	 *            'status' => 'bad|warning|good',
	 *            'msgs'   => array(
	 *                message_id => array( data_1 ),
	 *                message_id => array( data_1, data_2 ),
	 *            ),
	 *        ),
	 *        'fix' => array(
	 *            'status' => 'bad|warning|good|cantfix',
	 *            'msgs'   => array(
	 *                message_id => array( data_1 ),
	 *                message_id => array( data_1, data_2 ),
	 *            ),
	 *        ),
	 *    ),
	 * )
	 */

	// Maybe set current fix status.

	final protected function set_subsite_status( $status, $scan_or_fix = 'scan', $site_id = 0, $force = false ) {
		$statuses = array(
			'cantfix' => 0,
			'good'    => 1,
			'warning' => 2,
			'bad'     => 3,
		);

		// Unkown status
		if ( ! isset( $statuses[ $status ] ) ) {
			return false;
		}

		$scan_or_fix = 'fix' === $scan_or_fix ? 'fix' : 'scan';
		$site_id     = $site_id ? $site_id : get_current_blog_id();

		$this->set_subsite_defaults( $scan_or_fix, $site_id );

		// No previous status
		if ( empty( $this->fix_sites[ $site_id ][ $scan_or_fix ]['status'] ) || $force ) {
			$this->fix_sites[ $site_id ][ $scan_or_fix ]['status'] = $status;
		}
		// Status already set: only allow to "upgrade" to a superior status.
		elseif ( $statuses[ $status ] > $statuses[ $this->fix_sites[ $site_id ][ $scan_or_fix ]['status'] ] ) {
			$this->fix_sites[ $site_id ][ $scan_or_fix ]['status'] = $status;
		}

		return $this->fix_sites[ $site_id ][ $scan_or_fix ]['status'];
	}


	// Add a message and automatically set the fix status.

	final protected function add_subsite_message( $message_id, $params = array(), $scan_or_fix = 'scan', $site_id = 0 ) {
		$scan_or_fix = 'fix' === $scan_or_fix ? 'fix' : 'scan';
		$site_id     = $site_id ? $site_id : get_current_blog_id();

		$this->set_subsite_status( static::get_status_from_message_id( $message_id ), $scan_or_fix, $site_id );
		$this->fix_sites[ $site_id ][ $scan_or_fix ]['msgs'][ $message_id ] = $params;
	}


	// Are status and message(s) set?

	final protected function has_subsite_status( $scan_or_fix = 'scan', $site_id = 0 ) {
		$scan_or_fix = 'fix' === $scan_or_fix ? 'fix' : 'scan';
		$site_id     = $site_id ? $site_id : get_current_blog_id();
		return ! empty( $this->fix_sites[ $site_id ][ $scan_or_fix ] );
	}


	// Set a status + message only if no status is set yet.

	final protected function maybe_set_subsite_status( $message_id, $params = array(), $scan_or_fix = 'scan', $site_id = 0 ) {
		if ( ! $this->has_subsite_status( $scan_or_fix, $site_id ) ) {
			$this->add_subsite_message( $message_id, $params, $scan_or_fix, $site_id );
		}
	}


	// Set defaults.

	final protected function set_subsite_defaults( $scan_or_fix = 'scan', $site_id = 0 ) {
		$scan_or_fix = 'fix' === $scan_or_fix ? 'fix' : 'scan';
		$site_id     = $site_id ? $site_id : get_current_blog_id();

		$this->set_empty_data_for_subsite( $site_id );

		$this->fix_sites[ $site_id ][ $scan_or_fix ]           = isset( $this->fix_sites[ $site_id ][ $scan_or_fix ] )           ? $this->fix_sites[ $site_id ][ $scan_or_fix ]           : array();
		$this->fix_sites[ $site_id ][ $scan_or_fix ]['msgs']   = isset( $this->fix_sites[ $site_id ][ $scan_or_fix ]['msgs'] )   ? $this->fix_sites[ $site_id ][ $scan_or_fix ]['msgs']   : array();
		$this->fix_sites[ $site_id ][ $scan_or_fix ]['status'] = isset( $this->fix_sites[ $site_id ][ $scan_or_fix ]['status'] ) ? $this->fix_sites[ $site_id ][ $scan_or_fix ]['status'] : '';
	}


	/*
	 * Remove all previously stored messages for sub-sites.
	 * This will allow to set an empty transient, and then empty the option later.
	 */
	final protected function set_empty_data_for_subsites() {
		$this->fix_sites = array_fill_keys( static::get_blog_ids(), array() );
	}


	/*
	 * Remove all previously stored messages for a particular sub-site.
	 * This will allow to set an empty transient, and then empty the option later for this sub-site.
	 */
	final protected function set_empty_data_for_subsite( $site_id = 0 ) {
		$site_id = $site_id ? $site_id : get_current_blog_id();
		$this->fix_sites             = is_array( $this->fix_sites )          ? $this->fix_sites             : array();
		$this->fix_sites[ $site_id ] = isset( $this->fix_sites[ $site_id ] ) ? $this->fix_sites[ $site_id ] : array();
	}


	final protected function get_subsite_result( $scan_or_fix = 'scan', $site_id = 0 ) {
		$scan_or_fix        = 'fix' === $scan_or_fix ? 'fix' : 'scan';
		$scan_or_fix_invert = 'fix' === $scan_or_fix ? 'scan' : 'fix';
		$site_id            = $site_id ? $site_id : get_current_blog_id();

		$result  = $this->fix_sites[ $site_id ][ $scan_or_fix ];

		unset( $this->fix_sites[ $site_id ][ $scan_or_fix ] );
		if ( ! empty( $this->fix_sites[ $site_id ][ $scan_or_fix_invert ] ) ) {
			return $result;
		}

		unset( $this->fix_sites[ $site_id ] );
		if ( ! empty( $this->fix_sites ) ) {
			return $result;
		}

		$this->fix_sites = null;

		return $result;
	}


	// Scan and fix ================================================================================

	// Scan for flaw(s).

	public function scan() {
		$this->update();

		if ( $this->is_for_current_site() ) {
			$result = $this->get_subsite_result();
		} else {
			$result = $this->result;
			$this->result = array();
		}

		return $result;
	}


	// Try to fix the flaw(s).

	public function fix() {
		$this->update_fix();

		if ( $this->fix_actions ) {
			// Ajax
			if ( defined( 'DOING_AJAX' ) ) {
				// Add the fixes that require user action in the returned data.
				$form = array(
					'form_contents' => $this->get_required_fix_action_template_parts(),
					'form_fields'   => $this->get_fix_action_fields( false, false ),
					'form_title'    => _n( 'This action requires your attention', 'These actions require your attention', count( $this->fix_actions ), 'secupress' ),
				);

				if ( $this->is_for_current_site() ) {
					$site_id = get_current_blog_id();
					$this->set_subsite_defaults( 'fix', $site_id );
					$this->fix_sites[ $site_id ]['fix'] = array_merge( $this->fix_sites[ $site_id ]['fix'], $form );
				} else {
					$this->result_fix = array_merge( $this->result_fix, $form );
				}

				$this->fix_actions = array();
			}
			// No ajax
			else {
				// Set a transient with fixes that require user action.
				$this->set_fix_actions();
			}
		}

		if ( $this->is_for_current_site() ) {
			$result = $this->get_subsite_result( 'fix' );
		} else {
			$result = $this->result_fix;
			$this->result_fix = array();
		}

		return $result;
	}


	// Try to fix the flaw(s) after requiring user action.

	public function manual_fix() {
		// Don't use `$this->` here, we need to call the one from this class.
		return self::fix();
	}


	// Store IDs related to fixes that require user action.

	final protected function add_fix_action( $fix_id ) {
		$this->fix_actions[ $fix_id ] = $fix_id;
	}


	// Return an array containing ONLY THE REQUIRED forms that would fix the scan if it requires user action.

	final public function get_required_fix_action_template_parts( $fix_actions = false ) {
		$fix_actions = $fix_actions ? $fix_actions : $this->fix_actions;
		return array_intersect_key( $this->get_fix_action_template_parts(), $fix_actions );
	}


	// Return an array containing ALL the forms that would fix the scan if it requires user action.

	protected function get_fix_action_template_parts() {
		return array();
	}


	// Tell if a fix action part is needed.

	final protected function has_fix_action_part( $fix_id ) {
		$fix_ids = ! empty( $_POST['test-parts'] ) ? ',' . $_POST['test-parts'] . ',' : '';
		return false !== strpos( $fix_ids, ',' . $fix_id . ',' );
	}


	// Print the required fields for the user fix form.

	final public function get_fix_action_fields( $fix_actions = false, $echo = true ) {
		$fix_actions = $fix_actions ? $fix_actions : $this->fix_actions;
		$output  = '<input type="hidden" name="action" value="secupress_manual_fixit" />';
		$output .= '<input type="hidden" name="test" value="' . $this->class_name_part . '" />';
		$output .= '<input type="hidden" name="test-parts" value="' . implode( ',', $fix_actions ) . '" />';
		$output .= wp_nonce_field( 'secupress_manual_fixit-' . $this->class_name_part, 'secupress_manual_fixit-nonce', false, false );
		if ( $this->is_for_current_site() ) {
			$output .= '<input type="hidden" name="for-current-site" value="1" />';
		}

		if ( ! $echo ) {
			return $output;
		}
		echo $output;
	}

	// Options =====================================================================================

	// Set option.

	final public function update() {
		$name = strtolower( $this->class_name_part );

		if ( $this->is_for_current_site() ) {
			if ( ! isset( $this->fix_sites ) ) {
				return array();
			}

			$site_id       = get_current_blog_id();
			$sub_transient = secupress_get_site_transient( SECUPRESS_SCAN_FIX_SITES_SLUG . '_' . $name );
			$sub_transient = is_array( $sub_transient ) ? $sub_transient : array();

			$sub_transient[ $site_id ] = ! empty( $sub_transient[ $site_id ] ) ? $sub_transient[ $site_id ] : array();
			$sub_transient[ $site_id ]['scan'] = ! empty( $this->fix_sites[ $site_id ]['scan'] ) ? $this->fix_sites[ $site_id ]['scan'] : array();

			secupress_set_site_transient( SECUPRESS_SCAN_FIX_SITES_SLUG . '_' . $name, $sub_transient );

			return isset( $this->fix_sites[ $site_id ]['scan'] ) && is_array( $this->fix_sites[ $site_id ]['scan'] ) ? $this->fix_sites[ $site_id ]['scan'] : array();
		}

		secupress_set_site_transient( 'secupress_scan_' . $name, $this->result );

		return $this->result;
	}


	final public function update_fix() {
		$name = strtolower( $this->class_name_part );
		$name = strtolower( $this->class_name_part );

		if ( $this->is_for_current_site() ) {
			if ( ! isset( $this->fix_sites ) ) {
				return array();
			}

			$site_id       = get_current_blog_id();
			$sub_transient = secupress_get_site_transient( SECUPRESS_SCAN_FIX_SITES_SLUG . '_' . $name );
			$sub_transient = is_array( $sub_transient ) ? $sub_transient : array();

			$sub_transient[ $site_id ] = ! empty( $sub_transient[ $site_id ] ) ? $sub_transient[ $site_id ] : array();
			$sub_transient[ $site_id ]['fix'] = ! empty( $this->fix_sites[ $site_id ]['fix'] ) ? $this->fix_sites[ $site_id ]['fix'] : array();

			secupress_set_site_transient( SECUPRESS_SCAN_FIX_SITES_SLUG . '_' . $name, $sub_transient );

			return isset( $this->fix_sites[ $site_id ]['fix'] ) && is_array( $this->fix_sites[ $site_id ]['fix'] ) ? $this->fix_sites[ $site_id ]['fix'] : array();

		} elseif ( isset( $this->fix_sites ) ) {
			secupress_set_site_transient( SECUPRESS_SCAN_FIX_SITES_SLUG . '_' . $name, $this->fix_sites );
		}

		$this->result_fix['attempted_fixes'] = array_key_exists( 'attempted_fixes', $this->result_fix ) ? ++$this->result_fix['attempted_fixes'] : 1;

		secupress_set_site_transient( 'secupress_fix_' . $name, $this->result_fix );

		return $this->result_fix;
	}

	// Other transients ============================================================================

	// Fixes that require user action.

	final protected function set_fix_actions() {
		secupress_set_site_transient( 'secupress_fix_actions', $this->class_name_part . '|' . implode( ',', $this->fix_actions ) );
		$this->fix_actions = array();
	}


	final public static function get_and_delete_fix_actions() {
		$transient = secupress_get_site_transient( 'secupress_fix_actions' );
		if ( false !== $transient ) {
			secupress_delete_site_transient( 'secupress_fix_actions' );
		}
		return $transient ? explode( '|', $transient ) : array( 0 => false );
	}


	// Schedule an auto-scan that will be executed on page load.

	final public function schedule_autoscan() {
		$transient = secupress_get_site_transient( 'secupress_autoscans' );
		$transient = is_array( $transient ) ? $transient : array();

		$transient[ $this->class_name_part ] = $this->class_name_part;

		secupress_set_site_transient( 'secupress_autoscans', $transient );
	}


	final public static function get_and_delete_autoscans() {
		$transient = secupress_get_site_transient( 'secupress_autoscans' );
		if ( false !== $transient ) {
			secupress_delete_site_transient( 'secupress_autoscans' );
		}
		return is_array( $transient ) ? $transient : array();
	}


	// Tools =======================================================================================

	// Get prioritie(s).

	final public static function get_priorities( $level = null ) {
		$priorities = array(
			'high' => array(
				'title'       => __( 'High Priority', 'secupress' ),
				'description' => __( 'These tests should be fixed now.', 'secupress' ),
			),
			'medium' => array(
				'title'       => __( 'Medium Priority', 'secupress' ),
				'description' => __( 'These tests should be fixed when you can if no conflict are found', 'secupress' ),
			),
			'low' => array(
				'title'       => __( 'Low Priority', 'secupress' ),
				'description' => __( 'These tests should be fixed to improve your security, but not mandatory.', 'secupress' ),
			),
		);

		if ( isset( $level ) ) {
			return isset( $priorities[ $level ] ) ? $priorities[ $level ] : array( 'title' => __( 'Unkown Priority', 'secupress' ), 'description' => '' );
		}

		return $priorities;
	}


	// Given an array of items and wrap it in a HTML tag.

	final public static function wrap_in_tag( $array, $tag = 'code' ) {
		if ( $array ) {
			$array = (array) $array;

			foreach ( $array as $k => $item ) {
				$array[ $k ] = sprintf( '<%2$s>%1$s</%2$s>', $item, $tag );
			}
		}

		return $array ? $array : array();
	}


	// Slide the items if there are too many

	final public static function slice_and_dice( &$items, $max_count ) {
		$count = count( $items ) - $max_count;
		if ( $count > 0 ) {
			$items = array_slice( $items, 0, $max_count );
			array_push( $items, sprintf( _n( '%s other', '%s others', $count ), number_format_i18n( $count ) ) );
			// array_push( $items, '<button>more</button>&#160;&hellip;' ); //// css class to looks like link + js to deploy all the items (so finally don't really slice but hide in a span, ykwim)
		}
	}


	//

	final protected static function get_status_from_message_id( $message_id ) {
		if ( $message_id < 100 ) {
			return 'good';
		}
		if ( $message_id < 200 ) {
			return 'warning';
		}
		if ( $message_id < 300 ) {
			return 'bad';
		}
		if ( $message_id < 400 ) {
			return 'cantfix';
		}
	}


	// A shothand to get the WP file system class object.

	final protected static function get_filesystem() {
		global $wp_filesystem;

		if ( ! $wp_filesystem ) {
			require_once( ABSPATH . 'wp-admin/includes/class-wp-filesystem-base.php' );
			require_once( ABSPATH . 'wp-admin/includes/class-wp-filesystem-direct.php' );

			$wp_filesystem = new WP_Filesystem_Direct( new StdClass() );

			// Set the permission constants if not already set.
			if ( ! defined( 'FS_CHMOD_DIR' ) ) {
				define( 'FS_CHMOD_DIR', ( fileperms( ABSPATH ) & 0777 | 0755 ) );
			}
			if ( ! defined( 'FS_CHMOD_FILE' ) ) {
				define( 'FS_CHMOD_FILE', ( fileperms( ABSPATH . 'index.php' ) & 0777 | 0644 ) );
			}
		}

		return $wp_filesystem;
	}


	// Get the list of the blog IDs.

	final protected static function get_blog_ids() {
		global $wpdb;
		static $blogs;

		if ( isset( $blogs ) ) {
			return $blogs;
		}

		$blogs = $wpdb->get_col( $wpdb->prepare( "SELECT blog_id FROM $wpdb->blogs WHERE site_id = %d", $wpdb->siteid ) );
		$blogs = array_map( 'absint', $blogs );
		return $blogs;
	}


	/*
	 * A sandbox for doing crazy things with `.htaccess`.
	 * Create a folder containing a `.htaccess` file with the provided content and a `secupress.html` file.
	 * Then, make a request to the `secupress.html` file to test if a server error is triggered.
	 *
	 * @param  (string)        The content to put in the `.htaccess` file.
	 * @return (WP_Error|bool) Return true if the server does not trigger an error 500, false otherwise.
	 *                         Return a WP_Error object if the sandbox creation fails or if the HTTP request fails.
	 */

	final protected static function htaccess_success_in_sandbox( $content ) {
		$wp_filesystem = static::get_filesystem();
		$folder_name   = 'secupress-sandbox-' . uniqid();
		$folder_path   = ABSPATH . '/' . $folder_name;

		// Create folder.
		if ( ! $wp_filesystem->mkdir( $folder_path ) ) {
			return new WP_Error( 'dir_creation_failed', __( 'The sandbox could not be created.', 'secupress' ) );
		}

		// Create `secupress.html` file.
		if ( ! $wp_filesystem->put_contents( $folder_path . '/secupress.html', 'You are here.', FS_CHMOD_FILE ) ) {
			$wp_filesystem->delete( $folder_path, true );
			return new WP_Error( 'file_creation_failed', __( 'The sandbox could not be created.', 'secupress' ) );
		}

		// Create `.htaccess` file with our content.
		if ( ! $wp_filesystem->put_contents( $folder_path . '/.htaccess', $content, FS_CHMOD_FILE ) ) {
			$wp_filesystem->delete( $folder_path, true );
			return new WP_Error( 'htaccess_creation_failed', __( 'The sandbox could not be created.', 'secupress' ) );
		}

		// Try to reach `secupress.html`.
		$response = wp_remote_get( site_url( $folder_name . '/secupress.html' ), array( 'redirection' => 0 ) );

		// Now we can get rid of the files.
		$wp_filesystem->delete( $folder_path, true );

		// HTTP requests are probably blocked.
		if ( is_wp_error( $response ) ) {
			return $response;
		}

		// Finally, the answer we were looking for.
		return 500 !== wp_remote_retrieve_response_code( $response );
	}

}
