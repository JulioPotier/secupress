<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/**
 * Base scan interface.
 *
 * @package SecuPress
 * @since 1.0
 */
interface SecuPress_Scan_Interface {

	/**
	 * Get messages.
	 *
	 * @since 1.0
	 *
	 * @param (int) $message_id A message ID.
	 */
	public static function get_messages( $message_id = null );

	/**
	 * Scan for flaw(s).
	 *
	 * @since 1.0
	 */
	public function scan();

	/**
	 * Try to fix the flaw(s).
	 *
	 * @since 1.0
	 */
	public function fix();
}


/**
 * Base scan abstract class.
 *
 * @package SecuPress
 * @since 1.0
 */
abstract class SecuPress_Scan extends SecuPress_Singleton implements SecuPress_Scan_Interface {

	/** Constants. ============================================================================== */

	/**
	 * Class version.
	 *
	 * @var (string)
	 */
	const VERSION = '1.0.2';


	/** Properties. ============================================================================= */

	/**
	 * The part of the class that extends this one, like SecuPress_Scan_{$class_name_part}.
	 *
	 * @var (string)
	 */
	protected $class_name_part;

	/**
	 * Contains scan results.
	 *
	 * @var (array)
	 */
	protected $result = array();

	/**
	 * Contains fix results.
	 *
	 * @var (array)
	 */
	protected $result_fix = array();

	/**
	 * On multisite, some fixes can't be performed from the network admin.
	 * This array will contain a list of site IDs with scan messages.
	 *
	 * @var (array)
	 */
	protected $fix_sites;

	/**
	 * On multisite, if `$for_current_site` is true, then the scan/fix/etc are performed for the current site, not wetwork-widely.
	 * If needed, should be set right after instanciation.
	 * Does nothing on non-multisite installations.
	 *
	 * @var (bool)
	 */
	protected $for_current_site = false;

	/**
	 * Tells if a scanner is fixable by SecuPress. The value "pro" means it's fixable only with the version PRO.
	 *
	 * @var (bool|string)
	 */
	protected $fixable = true;

	/**
	 * Tells if the fix must occur after all other scans and fixes, while no other scan/fix is running.
	 *
	 * @var (bool)
	 */
	protected $delayed_fix = false;

	/**
	 * Scanner title.
	 *
	 * @var (string)
	 */
	public $title = '';

	/**
	 * Scan description.
	 *
	 * @var (string)
	 */
	public $more = '';

	/**
	 * Fix description.
	 *
	 * @var (string)
	 */
	public $more_fix = '';


	/** Init. =================================================================================== */

	/**
	 * Init: this method is required by the class `SecuPress_Singleton`.
	 *
	 * @since 1.0
	 */
	protected function _init() {
		$this->class_name_part = substr( get_called_class(), 15 ); // 15 is 'SecuPress_Scan_' length.
		$this->init();
	}


	/**
	 * Sub-classes init.
	 *
	 * @since 1.0
	 */
	protected function init() {
		die( 'Method SecuPress_Scan->init() must be over-ridden in a sub-class.' );
	}


	/** Multisite specifics. ==================================================================== */

	/**
	 * Get `$for_current_site`.
	 *
	 * @since 1.0
	 *
	 * @return (bool)
	 */
	final public function is_for_current_site() {
		return $this->for_current_site;
	}


	/**
	 * `is_network_admin()` does not work in an ajax callback.
	 *
	 * @since 1.0
	 *
	 * @return (bool)
	 */
	final public function is_network_admin() {
		return is_multisite() && ! $this->is_for_current_site();
	}


	/**
	 * Set `$for_current_site`.
	 *
	 * @since 1.0
	 *
	 * @param (bool) $for_current_site The new value for `$for_current_site`.
	 *
	 * @return $this
	 */
	final public function for_current_site( $for_current_site = null ) {
		$this->for_current_site = (bool) $for_current_site;
		return $this;
	}


	/** Getters. ================================================================================ */

	/**
	 * Tells if a scanner is fixable by SecuPress. The value "pro" means it's fixable only with the version PRO.
	 *
	 * @since 1.0
	 *
	 * @return (bool|string)
	 */
	public function is_fixable() {
		return $this->fixable;
	}


	/**
	 * Tells if the fix must occur after all other scans and fixes, while no other scan/fix is running.
	 *
	 * @since 1.0
	 *
	 * @return (bool)
	 */
	public function is_delayed_fix() {
		return $this->delayed_fix;
	}


	/**
	 * Get the documentation URL.
	 *
	 * @since 1.0
	 *
	 * @return (string)
	 */
	public static function get_docs_url() {
		return __( 'https://docs.secupress.me/', 'secupress' );
	}

	/**
	 * Get the timeout in seconds, filterable
	 *
	 * @since 1.0.4
	 *
	 * @return (int) Timeout in seconds
	 */
	public static function get_timeout() {
		/**
		 * Some scan are doing a request on the homepage or some internal files, we need sometimes to raise the timeout
		 *
		 * @since 1.0.4
		 *
		 * @param (int) Timeout in seconds
		 */
		return apply_filters( 'secupress.remote_timeout', 30 );
	}


	/** Messages for scans and fixes. =========================================================== */

	/**
	 * Get messages.
	 *
	 * @since 1.0
	 *
	 * @param (int) $message_id A message ID.
	 */
	public static function get_messages( $message_id = null ) {
		die( 'Method SecuPress_Scan::get_messages() must be over-ridden in a sub-class.' );
	}


	/** Status and messages for scans. ========================================================== */

	/**
	 * Maybe set current scan status, only if it isn't set yet.
	 * If the status was already set, only allow to "upgrade" to a superior status.
	 *
	 * @since 1.0
	 *
	 * @param (string) $status The status code.
	 * @param (bool)   $force  Set the status, even if it was already set.
	 *
	 * @return (string|bool) The current status. False on failure.
	 */
	final protected function set_status( $status, $force = false ) {
		if ( $this->is_for_current_site() ) {
			return $this->set_subsite_status( $status, 'scan', 0, $force );
		}

		$statuses = array(
			'cantfix' => 0,
			'good'    => 1,
			'warning' => 2,
			'bad'     => 3,
		);

		// Unkown status.
		if ( ! isset( $statuses[ $status ] ) ) {
			return false;
		}

		// No previous status.
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


	/**
	 * Add a scan message and automatically set the scan status.
	 *
	 * "good":    the scan performed correctly and returned a good result.
	 * "warning": the scan could not perform correctly.
	 * "bad":     the scan performed correctly but returned a bad result.
	 *
	 * @since 1.0
	 *
	 * @param (int)   $message_id The message ID.
	 * @param (array) $params     The arguments to use with `vsprintf()`.
	 */
	final protected function add_message( $message_id, $params = array() ) {
		if ( $this->is_for_current_site() ) {
			return $this->add_subsite_message( $message_id, $params );
		}

		$this->result['msgs'] = isset( $this->result['msgs'] ) ? $this->result['msgs'] : array();
		$this->result['msgs'][ $message_id ] = $params;
		$this->set_status( static::get_status_from_message_id( $message_id ) );
	}


	/**
	 * Are scan status and message(s) set?
	 *
	 * @since 1.0
	 *
	 * @return (bool)
	 */
	final protected function has_status() {
		if ( $this->is_for_current_site() ) {
			return $this->has_subsite_status();
		}

		return ! empty( $this->result );
	}


	/**
	 * Set a scan status + message only if no status is set yet.
	 *
	 * @since 1.0
	 *
	 * @param (int)   $message_id The message ID.
	 * @param (array) $params     The arguments to use with `vsprintf()`.
	 */
	final protected function maybe_set_status( $message_id, $params = array() ) {
		if ( $this->is_for_current_site() ) {
			return $this->maybe_set_subsite_status( $message_id, $params );
		}

		if ( ! $this->has_status() ) {
			$this->add_message( $message_id, $params );
		}
	}


	/** Status and messages for fixes. ========================================================== */

	/**
	 * Maybe set current fix status, only if it isn't set yet.
	 * If the status was already set, only allow to "upgrade" to a superior status.
	 *
	 * @since 1.0
	 *
	 * @param (string) $status The status code.
	 * @param (bool)   $force  Set the status, even if it was already set.
	 *
	 * @return (string|bool) The current status. False on failure.
	 */
	final protected function set_fix_status( $status, $force = false ) {
		if ( $this->is_for_current_site() ) {
			return $this->set_subsite_status( $status, 'fix', 0, $force );
		}

		$statuses = array(
			'cantfix' => 0,
			'good'    => 1,
			'warning' => 2,
			'bad'     => 3,
		);

		// Unkown status.
		if ( ! isset( $statuses[ $status ] ) ) {
			return false;
		}

		// No previous status.
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


	/**
	 * Add a fix message and automatically set the fix status.
	 *
	 * "good":    the fix performed correctly.
	 * "warning": partial fix. The fix could not perform entirely: some fix(es) worked and some not.
	 * "bad":     error. The fix could not perform correctly.
	 * "cantfix": neutral. The flaw cannot be fixed by this plugin.
	 *
	 * @since 1.0
	 *
	 * @param (int)   $message_id The message ID.
	 * @param (array) $params     The arguments to use with `vsprintf()`.
	 */
	public function add_fix_message( $message_id, $params = array() ) {
		if ( $this->is_for_current_site() ) {
			return $this->add_subsite_message( $message_id, $params, 'fix' );
		}

		$this->result_fix['msgs'] = isset( $this->result_fix['msgs'] ) ? $this->result_fix['msgs'] : array();
		$this->result_fix['msgs'][ $message_id ] = $params;
		$this->set_fix_status( static::get_status_from_message_id( $message_id ) );
	}


	/**
	 * Are fix status and message(s) set?
	 *
	 * @since 1.0
	 *
	 * @return (bool)
	 */
	final protected function has_fix_status() {
		if ( $this->is_for_current_site() ) {
			return $this->has_subsite_status( 'fix' );
		}

		return ! empty( $this->result_fix );
	}


	/**
	 * Set a fix status + message only if no status is set yet.
	 *
	 * @since 1.0
	 *
	 * @param (int)   $message_id The message ID.
	 * @param (array) $params     The arguments to use with `vsprintf()`.
	 */
	final protected function maybe_set_fix_status( $message_id, $params = array() ) {
		if ( $this->is_for_current_site() ) {
			return $this->maybe_set_subsite_status( $message_id, $params, 'fix' );
		}

		if ( ! $this->has_fix_status() ) {
			$this->add_fix_message( $message_id, $params );
		}
	}


	/**
	 * Add a pre fix message to inform the user before a fix (usually because the fix cannot be done).
	 *
	 * "good":    the fix performed correctly.
	 * "warning": partial fix. The fix could not perform entirely: some fix(es) worked and some not.
	 * "bad":     error. The fix could not perform correctly.
	 * "cantfix": neutral. The flaw cannot be fixed by this plugin.
	 *
	 * @since 1.0
	 *
	 * @param (int)   $message_id The message ID.
	 * @param (array) $params     The arguments to use with `vsprintf()`.
	 */
	public function add_pre_fix_message( $message_id, $params = array() ) {
		if ( $this->is_for_current_site() ) {
			return $this->add_subsite_message( $message_id, $params );
		}

		$this->result['fix_msg'] = isset( $this->result['fix_msg'] ) ? $this->result['fix_msg'] : array();
		$this->result['fix_msg'][ $message_id ] = $params;
		$this->result_fix['msgs'] = isset( $this->result['fix_msg'] ) ? $this->result['fix_msg'] : array();
		$this->result_fix['msgs'][ $message_id ] = $params;
		$this->update_fix();
	}


	/** Messages for subsites. ================================================================== */

	/**
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

	/**
	 * Maybe set current fix status.
	 *
	 * @since 1.0
	 *
	 * @param (string) $status      The status code.
	 * @param (string) $scan_or_fix For a scan or a fix.
	 * @param (int)    $site_id     The site ID.
	 * @param (bool)   $force  Set the status, even if it was already set.
	 *
	 * @return (string|bool) The current status. False on failure.
	 */
	final protected function set_subsite_status( $status, $scan_or_fix = 'scan', $site_id = 0, $force = false ) {
		$statuses = array(
			'cantfix' => 0,
			'good'    => 1,
			'warning' => 2,
			'bad'     => 3,
		);

		// Unkown status.
		if ( ! isset( $statuses[ $status ] ) ) {
			return false;
		}

		$scan_or_fix = 'fix' === $scan_or_fix ? 'fix' : 'scan';
		$site_id     = $site_id ? $site_id : get_current_blog_id();

		$this->set_subsite_defaults( $scan_or_fix, $site_id );

		// No previous status.
		if ( empty( $this->fix_sites[ $site_id ][ $scan_or_fix ]['status'] ) || $force ) {
			$this->fix_sites[ $site_id ][ $scan_or_fix ]['status'] = $status;
		}
		// Status already set: only allow to "upgrade" to a superior status.
		elseif ( $statuses[ $status ] > $statuses[ $this->fix_sites[ $site_id ][ $scan_or_fix ]['status'] ] ) {
			$this->fix_sites[ $site_id ][ $scan_or_fix ]['status'] = $status;
		}

		return $this->fix_sites[ $site_id ][ $scan_or_fix ]['status'];
	}


	/**
	 * Add a message and automatically set the fix status.
	 *
	 * @since 1.0
	 *
	 * @param (int)    $message_id The message ID.
	 * @param (array)  $params     The arguments to use with `vsprintf()`.
	 * @param (string) $scan_or_fix For a scan or a fix.
	 * @param (int)    $site_id     The site ID.
	 */
	final protected function add_subsite_message( $message_id, $params = array(), $scan_or_fix = 'scan', $site_id = 0 ) {
		$scan_or_fix = 'fix' === $scan_or_fix ? 'fix' : 'scan';
		$site_id     = $site_id ? $site_id : get_current_blog_id();

		$this->set_subsite_status( static::get_status_from_message_id( $message_id ), $scan_or_fix, $site_id );
		$this->fix_sites[ $site_id ][ $scan_or_fix ]['msgs'][ $message_id ] = $params;
	}


	/**
	 * Are status and message(s) set?
	 *
	 * @since 1.0
	 *
	 * @param (string) $scan_or_fix For a scan or a fix.
	 * @param (int)    $site_id     The site ID.
	 *
	 * @return (bool)
	 */
	final protected function has_subsite_status( $scan_or_fix = 'scan', $site_id = 0 ) {
		$scan_or_fix = 'fix' === $scan_or_fix ? 'fix' : 'scan';
		$site_id     = $site_id ? $site_id : get_current_blog_id();
		return ! empty( $this->fix_sites[ $site_id ][ $scan_or_fix ] );
	}


	/**
	 * Set a status + message only if no status is set yet.
	 *
	 * @since 1.0
	 *
	 * @param (int)    $message_id The message ID.
	 * @param (array)  $params     The arguments to use with `vsprintf()`.
	 * @param (string) $scan_or_fix For a scan or a fix.
	 * @param (int)    $site_id     The site ID.
	 */
	final protected function maybe_set_subsite_status( $message_id, $params = array(), $scan_or_fix = 'scan', $site_id = 0 ) {
		if ( ! $this->has_subsite_status( $scan_or_fix, $site_id ) ) {
			$this->add_subsite_message( $message_id, $params, $scan_or_fix, $site_id );
		}
	}


	/**
	 * Set defaults.
	 *
	 * @since 1.0
	 *
	 * @param (string) $scan_or_fix For a scan or a fix.
	 * @param (int)    $site_id     The site ID.
	 */
	final protected function set_subsite_defaults( $scan_or_fix = 'scan', $site_id = 0 ) {
		$scan_or_fix = 'fix' === $scan_or_fix ? 'fix' : 'scan';
		$site_id     = $site_id ? $site_id : get_current_blog_id();

		$this->set_empty_data_for_subsite( $site_id );

		$this->fix_sites[ $site_id ][ $scan_or_fix ]           = isset( $this->fix_sites[ $site_id ][ $scan_or_fix ] )           ? $this->fix_sites[ $site_id ][ $scan_or_fix ]           : array();
		$this->fix_sites[ $site_id ][ $scan_or_fix ]['msgs']   = isset( $this->fix_sites[ $site_id ][ $scan_or_fix ]['msgs'] )   ? $this->fix_sites[ $site_id ][ $scan_or_fix ]['msgs']   : array();
		$this->fix_sites[ $site_id ][ $scan_or_fix ]['status'] = isset( $this->fix_sites[ $site_id ][ $scan_or_fix ]['status'] ) ? $this->fix_sites[ $site_id ][ $scan_or_fix ]['status'] : '';
	}


	/**
	 * Remove all previously stored messages for sub-sites.
	 * This will allow to set an empty transient, and then empty the option later.
	 *
	 * @since 1.0
	 */
	final protected function set_empty_data_for_subsites() {
		$this->fix_sites = array_fill_keys( static::get_blog_ids(), array() );
	}


	/**
	 * Remove all previously stored messages for a particular sub-site.
	 * This will allow to set an empty transient, and then empty the option later for this sub-site.
	 *
	 * @since 1.0
	 *
	 * @param (int) $site_id The site ID.
	 */
	final protected function set_empty_data_for_subsite( $site_id = 0 ) {
		$site_id = $site_id ? $site_id : get_current_blog_id();
		$this->fix_sites             = is_array( $this->fix_sites )          ? $this->fix_sites             : array();
		$this->fix_sites[ $site_id ] = isset( $this->fix_sites[ $site_id ] ) ? $this->fix_sites[ $site_id ] : array();
	}


	/**
	 * Get a sub-site scan/fix results.
	 *
	 * @since 1.0
	 *
	 * @param (string) $scan_or_fix For a scan or a fix.
	 * @param (int)    $site_id     The site ID.
	 *
	 * @return (array)
	 */
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


	/** Scan and fix. =========================================================================== */

	/**
	 * Scan for flaw(s).
	 *
	 * @since 1.0
	 *
	 * @return (array) The scan results.
	 */
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


	/**
	 * Try to fix the flaw(s).
	 *
	 * @since 1.0
	 *
	 * @return (array) The fix results.
	 */
	public function fix() {
		$this->update_fix();

		if ( $this->is_for_current_site() ) {
			$result = $this->get_subsite_result( 'fix' );
		} else {
			$result = $this->result_fix;
			$this->result_fix = array();
		}

		return $result;
	}


	/**
	 * Return an array of actions if a manual fix is needed here. False otherwise.
	 * In case a scanner with a manual fix doesn't need to be fixed, return an empty array instead of false: this way, this scanner will never be listed in the automatic fixes (if the scan is not up to date for example).
	 *
	 * @since 1.0
	 *
	 * @return (bool|array)
	 */
	public function need_manual_fix() {
		return false;
	}


	/**
	 * Try to fix the flaw(s) after requiring user action.
	 *
	 * @since 1.0
	 *
	 * @return (array) The fix results.
	 */
	public function manual_fix() {
		$this->update_fix();

		if ( defined( 'DOING_AJAX' ) ) {
			$fix_actions = $this->need_manual_fix();

			if ( $fix_actions ) {
				// Add the fixes that require user action in the returned data.
				$form = $this->get_required_fix_action_template_parts( $fix_actions, false );

				if ( $this->is_for_current_site() ) {
					$site_id = get_current_blog_id();
					$this->set_subsite_defaults( 'fix', $site_id );
					$this->fix_sites[ $site_id ]['fix']['form_contents'] = $form;
				} else {
					$this->result_fix['form_contents'] = $form;
				}
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


	/**
	 * Get ONLY THE REQUIRED forms that would fix the scan if it requires user action.
	 *
	 * @since 1.0
	 *
	 * @param (array) $fix_actions An array of fix actions.
	 * @param (bool)  $echo        True to print the outpout, False to return it.
	 *
	 * @return (string) A string of HTML templates (form contents most of the time).
	 */
	final public function get_required_fix_action_template_parts( $fix_actions, $echo = true ) {
		$templates = array_intersect_key( $this->get_fix_action_template_parts(), $fix_actions );
		$templates = implode( '', $templates );

		if ( $templates ) {
			$templates .= $this->get_fix_action_fields( $fix_actions );
		}

		if ( ! $echo ) {
			return $templates;
		}
		echo $templates;
	}


	/**
	 * Get an array containing ALL the forms that would fix the scan if it requires user action.
	 *
	 * @since 1.0
	 *
	 * @return (array) An array of HTML templates (form contents most of the time).
	 */
	protected function get_fix_action_template_parts() {
		return array();
	}


	/**
	 * Tell if a fix action part is needed.
	 *
	 * @since 1.0
	 *
	 * @param (string) $fix_id A fix action identifier.
	 *
	 * @return (bool)
	 */
	final protected function has_fix_action_part( $fix_id ) {
		$fix_ids = ! empty( $_POST['test-parts'] ) ? ',' . $_POST['test-parts'] . ',' : ''; // WPCS: CSRF ok.
		return false !== strpos( $fix_ids, ',' . $fix_id . ',' );
	}


	/**
	 * Get the required fields for the user fix form (nonce, referrer, action, etc).
	 *
	 * @since 1.0
	 *
	 * @param (array) $fix_actions An array of fix actions.
	 *
	 * @return (string)
	 */
	final public function get_fix_action_fields( $fix_actions ) {
		$nonce  = 'secupress_manual_fixit_' . $this->class_name_part;
		$output = "\n";

		if ( $this->is_for_current_site() ) {
			$nonce  .= '-' . get_current_blog_id();
			$output .= '<input type="hidden" name="for-current-site" value="1" />' . "\n";
			$output .= '<input type="hidden" name="site" value="' . get_current_blog_id() . '" />' . "\n";
		}

		$output .= '<input type="hidden" name="action" value="secupress_manual_fixit" />' . "\n";
		$output .= '<input type="hidden" name="test" value="' . $this->class_name_part . '" />' . "\n";
		$output .= '<input type="hidden" name="test-parts" value="' . implode( ',', $fix_actions ) . '" />' . "\n";
		$output .= '<input type="hidden" name="_wpnonce" value="' . wp_create_nonce( $nonce ) . '" />' . "\n";
		$output .= '<input type="hidden" name="_wp_http_referer" value="' . esc_attr( wp_unslash( $_SERVER['REQUEST_URI'] ) ) . '" />' . "\n";

		return $output;
	}

	/** Options. ================================================================================ */

	/**
	 * Set options: scan results.
	 *
	 * @since 1.0
	 *
	 * @return (array) Scan results.
	 */
	final public function update() {
		$name = strtolower( $this->class_name_part );

		if ( $this->is_for_current_site() ) {
			if ( ! isset( $this->fix_sites ) ) {
				return array();
			}

			$site_id     = get_current_blog_id();
			$sub_results = SecuPress_Scanner_Results::get_sub_sites_results( $name );
			$sub_results = is_array( $sub_results ) ? $sub_results : array();

			$sub_results[ $site_id ]         = ! empty( $sub_results[ $site_id ] )             ? $sub_results[ $site_id ]             : array();
			$sub_results[ $site_id ]['scan'] = ! empty( $this->fix_sites[ $site_id ]['scan'] ) ? $this->fix_sites[ $site_id ]['scan'] : array();

			SecuPress_Scanner_Results::update_sub_sites_result( $name, $sub_results );

			return isset( $this->fix_sites[ $site_id ]['scan'] ) && is_array( $this->fix_sites[ $site_id ]['scan'] ) ? $this->fix_sites[ $site_id ]['scan'] : array();
		}

		SecuPress_Scanner_Results::update_scan_result( $name, $this->result );

		return $this->result;
	}


	/**
	 * Set options: fix results.
	 *
	 * @since 1.0
	 *
	 * @return (array) Fix results.
	 */
	final public function update_fix() {
		$name = strtolower( $this->class_name_part );

		if ( $this->is_for_current_site() ) {
			if ( ! isset( $this->fix_sites ) ) {
				return array();
			}

			$site_id     = get_current_blog_id();
			$sub_results = SecuPress_Scanner_Results::get_sub_sites_results( $name );
			$sub_results = is_array( $sub_results ) ? $sub_results : array();

			$sub_results[ $site_id ]        = ! empty( $sub_results[ $site_id ] )            ? $sub_results[ $site_id ]            : array();
			$sub_results[ $site_id ]['fix'] = ! empty( $this->fix_sites[ $site_id ]['fix'] ) ? $this->fix_sites[ $site_id ]['fix'] : array();

			SecuPress_Scanner_Results::update_sub_sites_result( $name, $sub_results );

			return isset( $this->fix_sites[ $site_id ]['fix'] ) && is_array( $this->fix_sites[ $site_id ]['fix'] ) ? $this->fix_sites[ $site_id ]['fix'] : array();
		}

		if ( isset( $this->fix_sites ) ) {
			SecuPress_Scanner_Results::update_sub_sites_result( $name, $this->fix_sites );
		}

		SecuPress_Scanner_Results::update_fix_result( $name, $this->result_fix );

		return $this->result_fix;
	}

	/** Other transients. ======================================================================= */

	/**
	 * Auto-scan: schedule an auto-scan that will be executed on page load.
	 *
	 * @since 1.0
	 */
	final public function schedule_autoscan() {
		if ( $this->is_for_current_site() ) {
			$transient = secupress_get_transient( 'secupress_autoscans' );
			$transient = is_array( $transient ) ? $transient : array();

			$transient[ $this->class_name_part ] = $this->class_name_part;

			secupress_set_transient( 'secupress_autoscans', $transient );
		} else {
			$transient = secupress_get_site_transient( 'secupress_autoscans' );
			$transient = is_array( $transient ) ? $transient : array();

			$transient[ $this->class_name_part ] = $this->class_name_part;

			secupress_set_site_transient( 'secupress_autoscans', $transient );
		}
	}


	/**
	 * Auto-scan: get auto-scans and delete the transient used to store them.
	 *
	 * @since 1.0
	 *
	 * @return (array) Scan results.
	 */
	final public static function get_and_delete_autoscans() {
		if ( is_multisite() && ! is_network_admin() ) {
			$transient = secupress_get_transient( 'secupress_autoscans' );
			if ( false !== $transient ) {
				secupress_delete_transient( 'secupress_autoscans' );
			}
		} else {
			$transient = secupress_get_site_transient( 'secupress_autoscans' );
			if ( false !== $transient ) {
				secupress_delete_site_transient( 'secupress_autoscans' );
			}
		}

		return is_array( $transient ) ? $transient : array();
	}


	/** Tools. ================================================================================== */

	/**
	 * Given an array of items, wrap them in a HTML tag.
	 *
	 * @since 1.0
	 *
	 * @param (array)  $items An array of items.
	 * @param (string) $tag   The tag.
	 *
	 * @return (array).
	 */
	final public static function wrap_in_tag( $items, $tag = 'code' ) {
		if ( $items ) {
			$items = (array) $items;

			foreach ( $items as $k => $item ) {
				$items[ $k ] = sprintf( '<%2$s>%1$s</%2$s>', $item, $tag );
			}
		}

		return $items ? $items : array();
	}


	/**
	 * Slice the items if there are too many. Will add a "XX others" item.
	 *
	 * @since 1.0
	 *
	 * @param (array) $items     An array of items.
	 * @param (int)   $max_count The maximum length of the array.
	 */
	final public static function slice_and_dice( &$items, $max_count ) {
		$count = count( $items ) - $max_count;
		if ( $count > 0 ) {
			$items = array_slice( $items, 0, $max_count );
			array_push( $items, sprintf( _n( '%s other', '%s others', $count ), number_format_i18n( $count ) ) );
		}
	}


	/**
	 * Get the status code from a message identifier.
	 *
	 * @since 1.0
	 *
	 * @param (int) $message_id The message ID.
	 */
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


	/**
	 * Get the list of the blog IDs.
	 *
	 * @since 1.0
	 *
	 * @return (array)
	 */
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


	/**
	 * A shorthand to get the default arguments to use in `wp_remote_get()` and friends.
	 *
	 * @since 1.1.3
	 * @author Grégory Viguier
	 *
	 * @return (array) An array of default arguments.
	 */
	protected function get_default_request_args() {
		$class_name   = get_class( $this );
		$request_args = array(
			'redirection' => 0,
			'timeout'     => static::get_timeout(),
			'sslverify'   => apply_filters( 'https_local_ssl_verify', false ),
			'user-agent'  => SECUPRESS_PLUGIN_NAME . '/' . SECUPRESS_VERSION,
			'cookies'     => $_COOKIE,
			'headers'     => array(
				'X-SecuPress-Origin' => $class_name,
			),
		);
		/**
		 * Filter the default arguments used in the scanners' internal requests.
		 *
		 * @since 1.1.3
		 *
		 * @param (array)  $request_args The request arguments.
		 * @param (string) $class_name   The scan class name.
		 */
		return apply_filters( 'secupress.scan.default_request_args', $request_args, $class_name );
	}


	/**
	 * A sandbox for doing crazy things with `.htaccess`.
	 * Create a folder containing a `.htaccess` file with the provided content and a `secupress.html` file.
	 * Then, make a request to the `secupress.html` file to test if a server error is triggered.
	 *
	 * @since 1.0
	 *
	 * @param (string) $content The content to put in the `.htaccess` file.
	 *
	 * @return (object|bool) Return true if the server does not trigger an error 500, false otherwise.
	 *                       Return a WP_Error object if the sandbox creation fails or if the HTTP request fails.
	 */
	final protected function htaccess_success_in_sandbox( $content ) {
		/**
		* Allows to bypass the sandbox
		* @param (bool) true by default, false to use it.
		* @param (string) A context.
		*/
		if ( false === apply_filters( 'secupress.use_sandbox', true, 'htaccess' ) ) {
			return true;
		}
		$wp_filesystem = secupress_get_filesystem();
		$folder_name   = 'secupress-sandbox-' . uniqid();
		$folder_path   = ABSPATH . '/' . $folder_name;

		// Create folder.
		if ( ! $wp_filesystem->mkdir( $folder_path ) ) {
			return new WP_Error( 'dir_creation_failed', __( 'The temporary directory could not be created.', 'secupress' ) );
		}

		// Create `secupress.html` file.
		if ( ! $wp_filesystem->put_contents( $folder_path . '/secupress.html', 'You are here.', FS_CHMOD_FILE ) ) {
			$wp_filesystem->delete( $folder_path, true );
			return new WP_Error( 'file_creation_failed', __( 'The temporary directory could not be created.', 'secupress' ) );
		}

		// Create `.htaccess` file with our content.
		if ( ! $wp_filesystem->put_contents( $folder_path . '/.htaccess', $content, FS_CHMOD_FILE ) ) {
			$wp_filesystem->delete( $folder_path, true );
			return new WP_Error( 'htaccess_creation_failed', __( 'The temporary directory could not be created.', 'secupress' ) );
		}

		// Try to reach `secupress.html`.
		$response = wp_remote_get( site_url( $folder_name . '/secupress.html' ), $this->get_default_request_args() );

		// Now we can get rid of the files.
		$wp_filesystem->delete( $folder_path, true );

		// HTTP requests are probably blocked.
		if ( is_wp_error( $response ) ) {
			return $response;
		}

		// Finally, the answer we were looking for.
		return 500 !== wp_remote_retrieve_response_code( $response );
	}


	/**
	 * Extract a `<pre/>` content from a message.
	 *
	 * @since 1.0
	 *
	 * @param (array) $error An array where `message` is the key of our message.
	 *
	 * @return (string) The `<pre/>` tag and its content, or `<code>Error</code>` if no `<pre/>` tag is found.
	 */
	final protected static function get_rules_from_error( $error ) {
		$rules = '<code>Error</code>';

		if ( preg_match( '@<pre>.+</pre>@ms', $error['message'], $matches ) ) {
			$rules = $matches[0];
		}

		return $rules;
	}


	/**
	 * Extract a `<code/>` content from a message.
	 *
	 * @since 1.0
	 * @author Grégory Viguier
	 *
	 * @param (array)  $error An array where `message` is the key of our message.
	 * @param (string) $class If not empty, the `<code>` tag with this specific html class will be searched.
	 *
	 * @return (string) The `<code/>` tag and its content, or an empty string if no `<code/>` tag is found.
	 */
	final protected static function get_code_tag_from_error( $error, $class = '' ) {
		$class = $class ? ' class="' . $class . '"' : '';
		$tag   = '';

		if ( preg_match( '@<code' . $class . '>.+</code>@ms', $error['message'], $matches ) ) {
			$tag = $matches[0];
		}

		return $tag;
	}


	/**
	 * Multisite: tell if the "centralized blog options" are fully filled.
	 *
	 * @since 1.0
	 * @author Grégory Viguier
	 *
	 * @return (bool) True if our network options contain all blog options, or if it's not a multisite. False otherwise.
	 */
	final protected static function are_centralized_blog_options_filled() {
		if ( ! is_multisite() ) {
			return true;
		}

		$plugins = get_site_option( 'secupress_active_plugins' );

		return is_array( $plugins ) && empty( $plugins['offset'] );
	}

		/**
	 * Filter every scan to bypass the scan and return "true"
	 *
	 * @param (string) $class The SecuPress class to be filtered.
	 *
	 * @return (bool) "false" by default (not modified), should be "true" to be used
	 * @author Julio Potier
	 **/
	final protected function filter_scanner( $class ) {
		return ! is_null( apply_filters( 'secupress.pre_scan.' . $class, null ) );
	}

}
