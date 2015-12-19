<?php
defined( 'ABSPATH' ) or die( 'Cheatin\' uh?' );


/**
 * 404s Logs list class.
 *
 * @package SecuPress
 * @since 1.0
 */

class SecuPress_404_Logs_List extends SecuPress_Logs_List {

	const VERSION = '1.0';
	/**
	 * Parameters in page URL.
	 */
	const PAGINATION_PARAM = '4logs-page';
	const ORDERBY_PARAM    = '4logs-orderby';
	const ORDER_PARAM      = '4logs-order';

	/**
	 * @var The reference to the *Singleton* instance of this class.
	 */
	protected static $_instance;
	/**
	 * @var Logs class name.
	 */
	protected $logs_classname = 'SecuPress_404_Logs';
	/**
	 * @var Logs type.
	 */
	protected $logs_type = '404';
	/**
	 * @var Default order directions.
	 */
	protected $def_orders = array(
		'date' => 'ASC',
		'user' => 'ASC',
		'uri'  => 'ASC',
	);


	// Private methods =============================================================================

	/**
	 * Get the parameters that can be used to order the logs.
	 *
	 * @since 1.0
	 *
	 * @return (array) An array containing a label.
	 */
	protected function _get_orderbys() {
		return array(
			'date' => array( 'label' => __( 'Date', 'secupress' ) ),
			'user' => array( 'label' => 'IP' ),
			'uri'  => array( 'label' => 'URI' ),
		);
	}

}
