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

abstract class SecuPress_Scan implements iSecuPress_Scan {

	const VERSION               = '1.0';
	const SECUPRESS_SCAN_LENGTH = 15; // 15 is 'SecuPress_Scan_' length.

	private       $fix_actions = array();

	protected     $result = array();
	protected     $fix    = false;

	public static $prio    = '';
	public static $type    = '';
	public static $title   = '';
	public static $more    = '';
	public static $fixable = true;


	// Instance ====================================================================================

	/**
	 * Returns the *Singleton* instance of this class.
	 *
	 * @return Singleton The *Singleton* instance.
	 */
	public static function get_instance() {
		if ( ! isset( static::$_instance ) ) {
			static::$_instance = new static;
		}

		return static::$_instance;
	}


	/**
	 * Protected constructor to prevent creating a new instance of the
	 * *Singleton* via the `new` operator from outside of this class.
	 */
	final private function __construct() {
		static::init();
	}


	/**
	 * Private clone method to prevent cloning of the instance of the
	 * *Singleton* instance.
	 *
	 * @return void
	 */
	final private function __clone() {}


	/**
	 * Private unserialize method to prevent unserializing of the *Singleton*
	 * instance.
	 *
	 * @return void
	 */
	final private function __wakeup() {}


	// Init ========================================================================================

	protected static function init() {
		die( 'Method SecuPress_Scan::init() must be over-ridden in a sub-class.' );
	}


	// Status and messages =========================================================================

	// Maybe set current status.

	public function set_status( $status, $force = false ) {
		$statuses = array(
			'good'    => 0,
			'warning' => 1,
			'bad'     => 2,
		);

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


	// Get messages.

	public static function get_messages( $message_id = null ){
		die( 'Method SecuPress_Scan::get_messages() must be over-ridden in a sub-class.' );
	}


	// Add a message and automatically set the status.

	public function add_message( $message_id, $params = array() ) {
		$this->result['msgs'] = isset( $this->result['msgs'] ) ? $this->result['msgs'] : array();
		$this->result['msgs'][ $message_id ] = $params;

		if ( $message_id < 100 ) {

			$this->set_status( 'good' );

		} elseif  ( $message_id < 200 ) {

			$this->set_status( 'warning' );

		} elseif ( $message_id < 300 ) {

			$this->set_status( 'bad' );

		}
	}


	// Are status and message(s) set?

	public function has_status() {
		return ! empty( $this->result );
	}


	// Set a status + message only if no status is set yet.

	public function maybe_set_status( $message_id, $params = array() ) {
		if ( ! $this->has_status() ) {
			$this->add_message( $message_id, $params );
		}
	}


	// Scan and fix ================================================================================

	// Scan for flow(s).

	public function scan() {
		$this->update();

		return $this->result;
	}


	// Try to fix the flow(s).

	public function fix() {
		if ( ! defined( 'DOING_AJAX' ) ) {
			// Set a transient with fixes that require user action.
			if ( $this->fix_actions ) {
				$class_name_part   = substr( get_called_class(), self::SECUPRESS_SCAN_LENGTH );
				set_transient( 'secupress_fix_actions', $class_name_part . '|' . implode( ',', $this->fix_actions ) );
				$this->fix_actions = array();
			}

			$this->fix = true;
			return $this->scan();
		} else {
			if ( $this->fix_actions ) {
				wp_send_json_success( 
					array( 
						'form_contents' => $this->get_fix_action_template_parts(), 
						'form_fields'   => $this->get_fix_action_fields( $this->fix_actions, false ),
						'form_title'    => _n( 'This action requires your attention', 'These actions require your attention', count( $this->fix_actions ), 'secupress' ),
						)
					);
			}
		}
	}


	// Try to fix the flow(s) after requiring user action.

	public function manual_fix() {}


	// Store IDs related to fixes that require user action.

	final protected function add_fix_action( $fix_id ) {
		$this->fix_actions[ $fix_id ] = $fix_id;
	}


	// Return an array containing the forms that would fix the scan if it requires user action.

	public function get_fix_action_template_parts() {
		return array();
	}


	// Tell if a fix action part is needed.

	protected function has_fix_action_part( $fix_id ) {
		$fix_ids = ! empty( $_POST['test-parts'] ) ? ',' . $_POST['test-parts'] . ',' : '';
		return false !== strpos( $fix_ids, ',' . $fix_id . ',' );
	}


	// Print the required fields for the user fix form.

	public function get_fix_action_fields( $fix_actions, $echo = true ) {
		$class_name_part = substr( get_called_class(), self::SECUPRESS_SCAN_LENGTH );
		$output  = '<input type="hidden" name="action" value="secupress_manual_fixit" />';
		$output .= '<input type="hidden" name="test" value="' . $class_name_part . '" />';
		$output .= '<input type="hidden" name="test-parts" value="' . implode( ',', array_keys( $fix_actions ) ) . '" />';
		$output .= wp_nonce_field( 'secupress_manual_fixit-' . $class_name_part, 'secupress_manual_fixit-nonce', false, false );
		if ( $echo ) {
			echo $output;
		} else {
			return $output;
		}
	}

	// Options =====================================================================================

	// Set option.

	public function update() {

		if ( $this->fix ) {
			$this->result['attempted_fixes'] = array_key_exists( 'attempted_fixes', $this->result ) ? ++$this->result['attempted_fixes'] : 1;
		}

		$name = strtolower( substr( get_called_class(), self::SECUPRESS_SCAN_LENGTH ) );

		if ( ! set_transient( 'secupress_scan_' . $name, $this->result ) ) {
			return false;
		}

		return $this->result;
	}


	// Tools =======================================================================================

	// Get prioritie(s).

	public static function get_priorities( $level = null ) {
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

	// Given an array of "things", wrap those "things" in a HTML tag.

	public static function wrap_in_tag( $array, $tag = 'code' ) {
		$out = array();

		if ( $array ) {
			foreach ( (array) $array as $thing ) {
				$out[] = sprintf( '<%2$s>%1$s</%2$s>', $thing, $tag );
			}
		}

		return $out;
	}

}
