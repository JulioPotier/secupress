<?php
defined( 'ABSPATH' ) or die( 'Cheatin\' uh?' );


/**
 * Actions Logs list class.
 *
 * @package SecuPress
 * @since 1.0
 */

class SecuPress_Action_Logs_List extends SecuPress_Logs_List {

	const VERSION = '1.0';
	/**
	 * Parameters in page URL.
	 */
	const PAGINATION_PARAM = 'alogs-page';
	const ORDERBY_PARAM    = 'alogs-orderby';
	const ORDER_PARAM      = 'alogs-order';
	/**
	 * @var The reference to the *Singleton* instance of this class.
	 */
	protected static $_instance;
	/**
	 * @var Logs class name.
	 */
	protected $logs_classname = 'SecuPress_Action_Logs';
	/**
	 * @var Logs type.
	 */
	protected $logs_type = 'action';
	/**
	 * @var Default order directions.
	 */
	protected $def_orders = array(
		'date'      => 'ASC',
		'criticity' => 'DESC',
		'user'      => 'ASC',
	);


	// Private methods =============================================================================

	/**
	 * Reorder logs depending of current orderby and order params.
	 *
	 * @since 1.0
	 */
	protected function _order_logs() {
		if ( 'criticity' === $this->orderby ) {
			$this->logs = array_map( array( $this, '_set_criticity_callback' ), $this->logs );
			uasort( $this->logs, array( $this, '_order_by_criticity_callback' ) );
		} else {
			parent::_order_logs();
		}
	}


	/**
	 * Get the parameters that can be used to order the logs.
	 *
	 * @since 1.0
	 *
	 * @return (array) An array containing a label.
	 */
	protected function _get_orderbys() {
		return array(
			'date'      => array( 'label' => __( 'Date', 'secupress' ) ),
			'criticity' => array( 'label' => __( 'Criticity', 'secupress' ) ),
			'user'      => array( 'label' => __( 'User', 'secupress' ) ),
		);
	}


	/**
	 * Get the header content used in the list.
	 *
	 * @since 1.0
	 *
	 * @param (object) `SecuPress_Action_Log` object.
	 * @param (int)    Row number.
	 *
	 * @return (string) The header content.
	 */
	public function _log_header( $log, $row_number ) {
		echo number_format_i18n( $row_number ) . '. ' . $log->get_criticity( 'icon' ) . ' [' . $log->get_time() . '] - ' . $log->get_user();
	}


	// Tools =======================================================================================

	/**
	 * Callback used to set the criticity parameter in a log array.
	 *
	 * @since 1.0
	 *
	 * @param (array) $log The log.
	 *
	 * @return (array) The log.
	 */
	public function _set_criticity_callback( $log ) {
		$log['critic'] = SecuPress_Action_Log::get_criticity_for( $log['type'], $log['code'] );
		return $log;
	}


	/**
	 * Callback used with `uasort()` to order the logs by criticity.
	 *
	 * @since 1.0
	 *
	 * @param (array) $log_a The first log.
	 * @param (array) $log_b The second log.
	 *
	 * @return (int)
	 */
	public function _order_by_criticity_callback( $log_a, $log_b ) {
		$orders = array(
			'high'   => 3,
			'normal' => 2,
			'low'    => 1,
		);
		if ( $orders[ $log_a['critic'] ] === $orders[ $log_b['critic'] ] ) {
			return 0;
		}
		if ( $orders[ $log_a['critic'] ] > $orders[ $log_b['critic'] ] ) {
			return 'ASC' === $this->order ? 1 : -1;
		}
		return 'ASC' === $this->order ? -1 : 1;
	}

}
