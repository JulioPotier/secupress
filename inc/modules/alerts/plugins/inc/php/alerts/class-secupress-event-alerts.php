<?php
defined( 'ABSPATH' ) or die( 'Cheatin\' uh?' );


/**
 * Event Alerts class.
 *
 * @package SecuPress
 * @since 1.0
 */
class SecuPress_Event_Alerts extends SecuPress_Alerts {

	const VERSION = '1.0';

	/**
	 * The reference to *Singleton* instance of this class.
	 *
	 * @var (object)
	 */
	protected static $_instance;

	/**
	 * Alert type (Event Alerts, Daily Reporting...).
	 *
	 * @var (string)
	 */
	protected $alert_type = 'event-alerts';

	/**
	 * Name of the option that stores the alerts.
	 *
	 * @var (string)
	 */
	protected $option_name = 'secupress_delayed_alerts';

	/**
	 * Delay in seconds between two notifications of alerts of the same type.
	 *
	 * @var (int)
	 */
	protected $delay;

	/**
	 * Tells if the notification includes delayed alerts.
	 *
	 * @var (bool)
	 */
	protected $is_delayed = false;


	// Init ========================================================================================.

	/**
	 * Launch main hooks.
	 *
	 * @since 1.0
	 */
	protected function _init() {
		parent::_init();

		add_action( 'secupress.deactivation', array( $this, '_deactivation' ) );
		add_action( 'secupress.modules.deactivate_submodule_event-alerts', array( $this, '_deactivation' ) );
	}


	/**
	 * Submodule deactivation.
	 *
	 * @since 1.0
	 */
	public function _deactivation() {
		// Force to send all notifications (so they won't be sent next time the submodule is activated). It will also delete the option in the DB.
		remove_action( 'shutdown', array( $this, '_maybe_notify' ) );
		add_action( 'shutdown',    array( $this, '_force_notify' ) );
	}


	// Notifications ===============================================================================.

	/**
	 * Send notifications if needed, store the remaining ones.
	 * Mix new alerts with old ones, then choose which ones should be sent:
	 * - the new alerts with the "important" attribute,
	 * - the old alerts whom the delay is exceeded.
	 *
	 * @since 1.0
	 */
	public function _maybe_notify() {
		$trigger_now = array();
		$delayed     = $this->_get_stored_alerts();
		/**
		 * Testing for:    current-time < alert-time + delay
		 * is the same as: current-time - delay < alert-time
		 * But in this last case, we do the substraction only once instead of doing the addition multiple times in a loop.
		 */
		$time = time() - $this->_get_delay();

		// Deal with new alerts that should pop now.
		if ( $this->alerts ) {
			foreach ( $this->alerts as $hook => $hooks ) {
				foreach ( $hooks as $i => $atts ) {
					// If this hook does not have previous iterations and should trigger an alert important, add it to the "trigger now" list.
					if ( empty( $delayed[ $hook ] ) && $this->hooks[ $hook ]['important'] ) {
						$trigger_now[ $hook ]   = isset( $trigger_now[ $hook ] ) ? $trigger_now[ $hook ] : array();
						$trigger_now[ $hook ][] = $atts;
					}
					// Store this alert with the others.
					$delayed[ $hook ]   = isset( $delayed[ $hook ] ) ? $delayed[ $hook ] : array();
					$delayed[ $hook ][] = $atts;
				}
			}
		}

		// Deal with old alerts that should pop now.
		if ( $delayed ) {
			foreach ( $delayed as $hook => $hooks ) {
				// Get the oldest alert of this type.
				$atts = reset( $hooks );

				// We haven't reached the delay yet.
				if ( $time < $atts['time'] ) {
					continue;
				}

				// If there is only one alert of this type and the notification has been sent, no need to do it again, just remove it.
				if ( $this->hooks[ $hook ]['important'] && count( $hooks ) === 1 ) {
					unset( $delayed[ $hook ] );
					continue;
				}

				// If "important", the first one has been notified already: remove it.
				if ( $this->hooks[ $hook ]['important'] ) {
					$key = key( $hooks );
					unset( $hooks[ $key ] );
				}

				// Now we have at least one alert to pop out.
				$trigger_now[ $hook ] = isset( $trigger_now[ $hook ] ) ? $trigger_now[ $hook ] : array();
				$trigger_now[ $hook ] = array_merge( $hooks, $trigger_now[ $hook ] );
				unset( $delayed[ $hook ] );
				$this->is_delayed = true;
			}
		}

		// Store the alerts.
		$this->_store_alerts( $delayed );

		// Notify.
		$this->_notify( $trigger_now );
	}


	/**
	 * Send notifications right away.
	 * Mix new alerts with old ones.
	 *
	 * @since 1.0
	 */
	public function _force_notify() {
		$alerts = $this->_get_stored_alerts();
		$alerts = $this->_merge_alerts( $alerts );

		$this->_delete_stored_alerts();
		$this->_notify( $alerts );
	}


	/**
	 * Get some strings for the email notification.
	 *
	 * @since 1.0
	 *
	 * @return (array)
	 */
	protected function _get_email_strings() {
		$blogname = $this->_get_blogname();
		$count    = $this->_get_alerts_number();

		$strings = array(
			/** Translators: %s is the blog name. */
			'subject'        => sprintf( _n( '[%s] New important event on your site', '[%s] New important events on your site', $count, 'secupress' ), $blogname ),
			'before_message' => '',
			'after_message'  => '',
		);

		if ( ! $this->is_delayed ) {
			$strings['before_message'] = _n( 'An important event just happened on your site:', 'Some important events just happened on your site:', $count, 'secupress' );
		} else {
			$mins = round( $this->_get_delay() / MINUTE_IN_SECONDS );
			/** Translators: %d is a number. */
			$strings['before_message'] = sprintf( _n( 'An important event happened on your site for the last %d minutes:', 'Some important events happened on your site for the last %d minutes:', $count, 'secupress' ), $mins );
		}

		return $strings;
	}


	// Tools =======================================================================================.

	/**
	 * Get the delay in seconds between two notifications of alerts of the same type.
	 *
	 * @since 1.0
	 *
	 * @return (int)
	 */
	protected function _get_delay() {
		if ( isset( $this->delay ) ) {
			return $this->delay;
		}

		$this->delay = (int) secupress_get_module_option( 'alerts_frequency', 15, 'alerts' );
		$this->delay = secupress_minmax_range( $this->delay, 5, 60 );
		$this->delay = $this->delay * MINUTE_IN_SECONDS;

		return $this->delay;
	}
}
