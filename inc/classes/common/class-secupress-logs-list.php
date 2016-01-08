<?php
defined( 'ABSPATH' ) or die( 'Cheatin\' uh?' );


/**
 * General Logs list class.
 *
 * @package SecuPress
 * @since 1.0
 */

class SecuPress_Logs_List extends SecuPress_Singleton {

	const VERSION = '1.0';
	/**
	 * Parameters in page URL: must be extended.
	 */
	const PAGINATION_PARAM = 'logs-page';
	const ORDERBY_PARAM    = 'logs-orderby';
	const ORDER_PARAM      = 'logs-order';
	/**
	 * @var The reference to the *Singleton* instance of this class: must be extended.
	 */
	protected static $_instance;
	/**
	 * @var Logs class name: must be extended.
	 */
	protected $logs_classname = 'SecuPress_Logs';
	/**
	 * @var Logs type: must be extended.
	 */
	protected $logs_type = '';
	/**
	 * @var Log class name.
	 */
	protected $log_classname = '';
	/**
	 * @var Will contain the logs.
	 */
	protected $logs = array();
	/**
	 * @var Logs count.
	 */
	protected $count = 0;
	/**
	 * @var Pagination: number of logs per page.
	 */
	protected $logs_per_page = 20; ////
	/**
	 * @var Pagination: last page number.
	 */
	protected $max_page = 1;
	/**
	 * @var Pagination: current page number.
	 */
	protected $page = 1;
	/**
	 * @var Pagination: logs offset.
	 */
	protected $offset = 0;
	/**
	 * @var Order links: current order.
	 */
	protected $orderby;
	/**
	 * @var Order links: current order direction.
	 */
	protected $order;
	/**
	 * @var Default order.
	 */
	protected $def_orderby = 'date';
	/**
	 * @var Default order directions.
	 */
	protected $def_orders = array(
		'date' => 'ASC',
		'user' => 'ASC',
	);
	/**
	 * @var Page URL without page/orderby/order parameters.
	 */
	protected static $page_url;


	// Init ========================================================================================

	/**
	 * Set the values.
	 *
	 * @since 1.0
	 */
	protected function _init() {
		static $init_done = false;

		$logs_classname      = $this->logs_classname;
		$this->log_classname = $logs_classname::_maybe_include_log_class();
		$this->logs_type     = $logs_classname::LOGS_TYPE;

		// Stored logs.
		$this->logs  = $logs_classname::get_logs();
		$this->logs  = is_array( $this->logs ) ? $this->logs : array();

		// Number of logs.
		$this->count = count( $this->logs );
		/**
		 * Filter the number of logs per page.
		 *
		 * @since 1.0
		 *
		 * @param (int) $this->logs_per_page Default number of logs per page.
		 * @param (int) $this->count         Total number of logs.
		 */
		$this->logs_per_page = apply_filters( 'secupress.logs.logs-per-page', $this->logs_per_page, $this->count );
		$this->logs_per_page = secupress_minmax_range( $this->logs_per_page, 10, 100 );

		// Number of the last page.
		$this->max_page = (int) ceil( $this->count / $this->logs_per_page );

		// Current page number.
		$this->page     = ! empty( $_GET[ static::PAGINATION_PARAM ] ) ? $_GET[ static::PAGINATION_PARAM ] : $this->page;
		$this->page     = secupress_minmax_range( $this->page, 1, $this->max_page );

		// Orderby.
		if ( ! empty( $_GET[ static::ORDERBY_PARAM ] ) ) {
			$this->orderby = $_GET[ static::ORDERBY_PARAM ];
			$this->orderby = isset( $this->def_orders[ $this->orderby ] ) ? $this->orderby : $this->def_orderby;
		} else {
			$this->orderby = $this->def_orderby;
		}

		// Order.
		if ( ! empty( $_GET[ static::ORDER_PARAM ] ) ) {
			$this->order   = strtoupper( $_GET[ static::ORDER_PARAM ] );
			$this->order   = 'DESC' === $this->order || 'ASC' === $this->order ? $this->order : $this->def_orders[ $this->orderby ];
		} else {
			$this->order   = $this->def_orders[ $this->orderby ];
		}

		// Order logs.
		if ( $this->logs ) {
			$this->_order_logs();

			// Logs offset.
			$this->offset = ( $this->page - 1 ) * $this->logs_per_page;
			$this->logs   = array_slice( $this->logs, $this->offset, $this->logs_per_page, true );
		}

		if ( $init_done ) {
			return;
		}
		$init_done = true;

		// Current page URL without page/orderby/order parameters.
		static::$page_url = esc_url( secupress_admin_url( 'modules', 'logs' ) );

		// JS
		wp_localize_script( 'secupress-modules-js', 'l10nLogs', array(
			'expandCodeText'      => __( 'Expand or collapse code block', 'secupress' ),
			'noLogsText'          => __( 'Nothing happened yet.', 'secupress' ),

			'clearConfirmText'    => __( 'You are about to delete all your logs.', 'secupress' ),
			'clearConfirmButton'  => __( 'Yes, delete all logs', 'secupress' ),
			'clearImpossible'     => __( 'Impossible to delete all logs.', 'secupress' ),
			'clearingText'        => __( 'Deleting all logs&hellip;', 'secupress' ),
			'clearedText'         => __( 'All logs deleted', 'secupress' ),

			'deleteConfirmText'   => __( 'You are about to delete a log.', 'secupress' ),
			'deleteConfirmButton' => __( 'Yes, delete this log', 'secupress' ),
			'deleteImpossible'    => __( 'Impossible to delete this log.', 'secupress' ),
			'deletingText'        => __( 'Deleting log&hellip;', 'secupress' ),
			'deletedText'         => __( 'Log deleted', 'secupress' ),
		) );
	}


	// Public methods ==============================================================================

	/**
	 * Print the logs list.
	 *
	 * @since 1.0
	 */
	public function output() {
		if ( ! $this->logs ) {
			echo '<p><em>' . __( 'Nothing happened yet.', 'secupress' ) . '</em></p>';
			return;
		}

		// Number of logs.
		$this->_logs_number();
		// Pagination.
		$this->_pagination();
		// Buttons to reorder the logs.
		$this->_order_links();

		$row_number = $this->offset + 1;
		$classname  = $this->log_classname;

		// The list.
		echo "<ul class=\"secupress-logs\">\n";
			foreach ( $this->logs as $timestamp => $log ) {
				$log = new $classname( $timestamp, $log );
				echo '<li>';
					echo '<em class="secupress-row-header">';
						$this->_log_header( $log, $row_number );
					echo '</em> ';
					echo $log->get_message();
					echo '<span class="actions">';
						$this->_delete_log_button( $timestamp );
					echo '</span>';
				echo "</li>\n";
				++$row_number;
			}
		echo "</ul>\n";

		// Pagination.
		$this->_secondary_pagination();

		echo '<p>';
			// Button to clear logs.
			$this->_clear_logs_button();

			// Button to download logs.
			$this->_download_logs_button();
		echo "</p>\n";
	}


	// Private methods =============================================================================

	/**
	 * Reorder logs depending of current orderby and order params.
	 *
	 * @since 1.0
	 */
	protected function _order_logs() {
		if ( $this->def_orderby === $this->orderby && $this->def_orders[ $this->def_orderby ] !== $this->order ) {
			krsort( $this->logs );
		} elseif ( $this->def_orderby !== $this->orderby ) {
			uasort( $this->logs, array( $this, '_order_callback' ) );
		}
	}


	/**
	 * Print the number of logs.
	 *
	 * @since 1.0
	 */
	protected function _logs_number() {
		echo '<p>';
			printf(
				/* translators: %s is a number */
				_n( '%s Log', '%s Logs', $this->count, 'secupress' ),
				'<span class="logs-count">' . number_format_i18n( $this->count ) . '</span>'
			);
		echo "</p>\n";
	}


	/**
	 * Print the list pagination.
	 *
	 * @since 1.0
	 */
	protected function _pagination() {
		if ( 1 === $this->max_page ) {
			return;
		}

		echo '<p class="logs-pagination">';
			echo '<span class="screen-reader-text">' . __( 'Logs list pagination', 'secupress' ) . '</span>';

			$order_params = $this->_get_order_params( $this->orderby );
			$page         = 1;

			while ( $page <= $this->max_page ) {
				$min_log = ( $page - 1 ) * $this->logs_per_page + 1;
				$min_log = number_format_i18n( $min_log );
				$max_log = min( $this->count, $page * $this->logs_per_page );
				$max_log = number_format_i18n( $max_log );

				if ( $page === $this->page ) {
					/* translators: %s is the page number */
					echo '<span class="button disabled" title="' . esc_attr( sprintf( __( 'Current page (%s)', 'secupress' ), number_format_i18n( $this->page ) ) ) . '">';
						echo '[' . $min_log . ' - ' . $max_log . ']';
					echo '</span> ';
				} else {
					echo '<a class="button" href="' . static::$page_url . static::_get_page_param( $page ) . $order_params . '">';
						echo '[' . $min_log . ' - ' . $max_log . ']';
					echo '</a> ';
				}
				++$page;
			}
		echo "</p>\n";
	}


	/**
	 * Print the list secondary pagination.
	 * Will be shown only if a certain number of logs in the page is reached.
	 *
	 * @since 1.0
	 */
	protected function _secondary_pagination() {
		if ( 1 === $this->max_page ) {
			return;
		}

		// If we display in this page more logs than this `$limit`, the pagination will be shown.
		$limit = $this->logs_per_page / 4;

		if ( $this->count - $this->offset >= $limit ) {
			$this->_pagination();
		}
	}


	/**
	 * Print the buttons to reorder the logs.
	 *
	 * @since 1.0
	 */
	protected function _order_links() {
		if ( $this->count <= 2 ) {
			return;
		}

		$suffix   = array(
			'DESC' => array( 'arrow' => ' <span class="order-arrow dashicons-before dashicons-arrow-down" aria-hidden="true"></span>', 'opposite' => 'ASC', ),
			'ASC'  => array( 'arrow' => ' <span class="order-arrow dashicons-before dashicons-arrow-up" aria-hidden="true"></span>',   'opposite' => 'DESC', )
		);
		$orderbys = $this->_get_orderbys();

		echo '<p class="logs-order">';

			echo '<span class="screen-reader-text">';
				printf(
					/* translators: 1 is "Date" or "User" ; 2 is "ascending" or "descending". */
					__( 'Current order: by %1$s, %2$s.', 'secupress' ),
					$orderbys[ $this->orderby ]['label'],
					( 'ASC' === $this->order ? __( 'ascending', 'secupress' ) : __( 'descending', 'secupress' ) )
				);
			echo "</span>\n";

			echo '<span>' . __( 'Order logs by:', 'secupress' ) . "</span>\n";

			echo "<span>\n";
				$orderbys[ $this->orderby ]['label'] .= $suffix[ $this->order ]['arrow'];
				$orderbys[ $this->orderby ]['class']  = ' active-filter';

				foreach ( $orderbys as $orderby => $atts ) {
					echo ' <a class="button' . ( ! empty( $atts['class'] ) ? $atts['class'] : '' ) . '" href="' . static::$page_url . $this->_get_order_params( $orderby, true ) . '">' . $atts['label'] . "</a>\n";
				}
			echo "</span>\n";

		echo "</p>\n";
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
			'date' => array( 'label' => __( 'Date', 'secupress' ) ),
			'user' => array( 'label' => __( 'User', 'secupress' ) ),
		);
	}


	/**
	 * Get the header content used in the list.
	 *
	 * @since 1.0
	 *
	 * @param (object) `SecuPress_Log` object.
	 * @param (int)    Row number.
	 *
	 * @return (string) The header content.
	 */
	public function _log_header( $log, $row_number ) {
		echo number_format_i18n( $row_number ) . '. [' . $log->get_time() . '] - ' . $log->get_user();
	}


	/**
	 * Print a "Delete log" link.
	 *
	 * @since 1.0
	 *
	 * @param (string) $timestamp The log timestamp (with the #).
	 */
	protected function _delete_log_button( $timestamp ) {
		$href = urlencode( secupress_admin_url( 'modules', 'logs' ) );
		$href = admin_url( 'admin-post.php?action=secupress_delete-' . $this->logs_type . '-log&log=' . urlencode( $timestamp ) . '&_wp_http_referer=' . $href );
		$href = wp_nonce_url( $href, 'secupress-delete-' . $this->logs_type . '-log' );

		echo '<a class="secupress-delete-log" href="' . $href . '">' . __( 'Delete this Log', 'secupress' ) . "</a> <span class=\"spinner secupress-inline-spinner\"></span>\n";
	}


	/**
	 * Print a "Clear Logs" button.
	 *
	 * @since 1.0
	 */
	protected function _clear_logs_button() {
		$href = urlencode( secupress_admin_url( 'modules', 'logs' ) );
		$href = admin_url( 'admin-post.php?action=secupress_clear-' . $this->logs_type . '-logs&_wp_http_referer=' . $href );
		$href = wp_nonce_url( $href, 'secupress-clear-' . $this->logs_type . '-logs' );

		echo '<a class="button secupress-clear-logs" href="' . $href . '">' . __( 'Clear Logs', 'secupress' ) . "</a> <span class=\"spinner secupress-inline-spinner\"></span>\n";
	}


	/**
	 * Print a "Download Logs" button.
	 *
	 * @since 1.0
	 */
	protected function _download_logs_button() {
		$href = admin_url( 'admin-post.php?action=secupress_download-' . $this->logs_type . '-logs' );
		$href = wp_nonce_url( $href, 'secupress-download-' . $this->logs_type . '-logs' );

		echo '<a class="button secupress-download-logs" href="' . $href . '">' . __( 'Download Logs', 'secupress' ) . "</a>\n";
	}


	// Tools =======================================================================================

	/**
	 * Get the "logs-page" parameter string, as an URL parameter.
	 * For the first page this parameter is useless, so the method returns an empty string in that case.
	 *
	 * @since 1.0
	 *
	 * @param (int) $page The page number.
	 *
	 * @return (string)
	 */
	protected static function _get_page_param( $page ) {
		return 1 === $page ? '' : '&amp;' . static::PAGINATION_PARAM . '=' . $page;
	}


	/**
	 * Get the "logs-orderby" and "logs-order" parameters string, as URL parameters.
	 *
	 * @since 1.0
	 *
	 * @param (string) $orderby       The orderby parameter.
	 * @param (bool)   $reverse_order If true, the order parameter will reversed from the current value (used for the order buttons).
	 *
	 * @return (string)
	 */
	protected function _get_order_params( $orderby, $reverse_order = false ) {
		$params  = '';
		$reverse = array(
			'DESC' => 'asc',
			'ASC'  => 'desc',
		);

		if ( $orderby !== $this->def_orderby ) {
			$params .= '&amp;' . static::ORDERBY_PARAM . '=' . $orderby;
		}

		if ( $orderby === $this->orderby ) {
			if ( $reverse_order && $this->order === $this->def_orders[ $orderby ] ) {
				$params .= '&amp;' . static::ORDER_PARAM . '=' . $reverse[ $this->order ];
			} elseif ( ! $reverse_order && $this->order !== $this->def_orders[ $orderby ] ) {
				$params .= '&amp;' . static::ORDER_PARAM . '=' . strtolower( $this->order );
			}
		}

		return $params;
	}


	/**
	 * Callback used with `uasort()` to order the logs.
	 *
	 * @since 1.0
	 *
	 * @param (array) $log_a The first log.
	 * @param (array) $log_b The second log.
	 *
	 * @return (int)
	 */
	public function _order_callback( $log_a, $log_b ) {
		if ( 'ASC' === $this->order ) {
			return strcasecmp( $log_a[ $this->orderby ], $log_b[ $this->orderby ] );
		}
		return strcasecmp( $log_b[ $this->orderby ], $log_a[ $this->orderby ] );
	}

}
