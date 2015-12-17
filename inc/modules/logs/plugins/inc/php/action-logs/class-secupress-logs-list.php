<?php
defined( 'ABSPATH' ) or die( 'Cheatin\' uh?' );


/**
 * Logs list class.
 *
 * @package SecuPress
 * @since 1.0
 */

class SecuPress_Logs_List extends SecuPress_Singleton {

	const VERSION = '1.0';
	/**
	 * Parameters in page URL.
	 */
	const PAGINATION_PARAM = 'logs-page';
	const ORDERBY_PARAM    = 'logs-orderby';
	const ORDER_PARAM      = 'logs-order';

	/**
	 * @var The reference to the *Singleton* instance of this class.
	 */
	protected static $_instance;
	/**
	 * @var Will store the logs.
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
	protected static $def_orderby = 'date';
	/**
	 * @var Default order directions.
	 */
	protected static $def_orders = array(
		'date'      => 'ASC',
		'criticity' => 'DESC',
		'user'      => 'ASC',
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
		SecuPress_Logs::_maybe_include_log_class();

		// Stored logs.
		$this->logs  = SecuPress_Logs::get_saved_logs();
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
			$this->orderby = isset( static::$def_orders[ $this->orderby ] ) ? $this->orderby : static::$def_orderby;
		} else {
			$this->orderby = static::$def_orderby;
		}

		// Order.
		if ( ! empty( $_GET[ static::ORDER_PARAM ] ) ) {
			$this->order   = strtoupper( $_GET[ static::ORDER_PARAM ] );
			$this->order   = 'DESC' === $this->order || 'ASC' === $this->order ? $this->order : static::$def_orders[ $this->orderby ];
		} else {
			$this->order   = static::$def_orders[ $this->orderby ];
		}

		// Order logs.
		if ( $this->logs ) {
			if ( 'date' === $this->orderby && 'DESC' === $this->order ) {
				krsort( $this->logs );
			} elseif ( 'criticity' === $this->orderby ) {
				$this->logs = array_map( array( __CLASS__, '_set_criticity_callback' ), $this->logs );

				if ( 'ASC' === $this->order ) {
					uasort( $this->logs, array( __CLASS__, '_order_by_criticity_asc_callback' ) );
				} else {
					uasort( $this->logs, array( __CLASS__, '_order_by_criticity_desc_callback' ) );
				}
			} elseif ( 'user' === $this->orderby ) {
				if ( 'ASC' === $this->order ) {
					uasort( $this->logs, array( __CLASS__, '_order_by_user_asc_callback' ) );
				} else {
					uasort( $this->logs, array( __CLASS__, '_order_by_user_desc_callback' ) );
				}
			}

			// Logs offset.
			$this->offset = ( $this->page - 1 ) * $this->logs_per_page;
			$this->logs   = array_slice( $this->logs, $this->offset, $this->logs_per_page, true );
		}

		// Current page URL without page/orderby/order parameters.
		static::$page_url = esc_url( secupress_admin_url( 'modules', 'logs' ) );

		// JS
		wp_localize_script( 'secupress-modules-js', 'l10nAlogs', array(
			'noLogsText'       => __( 'Nothing happened yet.', 'secupress' ),
			'errorText'        => __( 'Error', 'secupress' ),
			'clearConfirmText' => __( 'Do you really want to delete all your Action Logs?', 'secupress' ),
			'clearingText'     => __( 'Clearing Logs...', 'secupress' ),
			'clearedText'      => __( 'Logs cleared', 'secupress' ),
		) );
	}


	// Public methods ==============================================================================

	/**
	 * Print the logs list.
	 *
	 * @since 1.0
	 */
	public function output_list() {
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

		$min_log = $this->offset + 1;

		// The list.
		echo "<ul class=\"secupress-logs\">\n";
			foreach ( $this->logs as $timestamp => $log ) {
				$log = new SecuPress_Log( $timestamp, $log );
				echo '<li>';
					echo '<em class="secupress-row-header">' . number_format_i18n( $min_log ) . '. ' . $log->get_criticity( 'icon' ) . ' [' . $log->get_time() . '] - ' . $log->get_user() . '</em> ';
					echo $log->get_message();
				echo "</li>\n";
				++$min_log;
			}
		echo "</ul>\n";

		// Button to clear logs.
		static::_clear_logs_button();
	}


	/**
	 * Print the logs list as a table.
	 *
	 * @since 1.0
	 */
	public function output_table() {
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

		// The list.
		echo '<table class="wp-list-table widefat secupress-logs">';
			echo '<thead><tr><th scope="col" class="secupress-log-criticity">' . __( 'Criticity', 'secupress' ) . '</th><th scope="col" class="secupress-log-time">' . __( 'Time', 'secupress' ) . '</th><th scope="col" class="secupress-log-user">' . __( 'User', 'secupress' ) . '</th><th scope="col" class="secupress-log-message">' . __( 'Log message', 'secupress' ) .  '</th></tr></thead>';
			echo '<tfoot><tr><th scope="col" class="secupress-log-criticity">' . __( 'Criticity', 'secupress' ) . '</th><th scope="col" class="secupress-log-time">' . __( 'Time', 'secupress' ) . '</th><th scope="col" class="secupress-log-user">' . __( 'User', 'secupress' ) . '</th><th scope="col" class="secupress-log-message">' . __( 'Log message', 'secupress' ) .  '</th></tr></tfoot>';

			$class = ' class="alternate"';
			foreach ( $this->logs as $timestamp => $log ) {
				$class = $class ? '' : ' class="alternate"';
				$log   = new SecuPress_Log( $timestamp, $log );

				echo '<tr' . $class . '>';
					echo '<td>' . $log->get_criticity() . '</td>';
					echo '<td>' . $log->get_time() . '</td>';
					echo '<td>' . $log->get_user() . '</td>';
					echo '<td>' . $log->get_message() . '</td>';
				echo '</tr>';
			}
		echo '</table>';

		// Button to clear logs.
		static::_clear_logs_button();
	}


	// Private methods =============================================================================

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
				number_format_i18n( $this->count )
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
	 * Print the buttons to reorder the logs.
	 *
	 * @since 1.0
	 */
	protected function _order_links() {
		if ( $this->count <= 2 ) {
			return;
		}

		$suffix   = array(
			'DESC'      => array( 'arrow' => ' <span class="order-arrow dashicons-before dashicons-arrow-down" aria-hidden="true"></span>', 'opposite' => 'ASC', ),
			'ASC'       => array( 'arrow' => ' <span class="order-arrow dashicons-before dashicons-arrow-up" aria-hidden="true"></span>',   'opposite' => 'DESC', )
		);
		$orderbys = array(
			'date'      => array( 'label' => __( 'Date', 'secupress' ),      'class' => '' ),
			'criticity' => array( 'label' => __( 'Criticity', 'secupress' ), 'class' => '' ),
			'user'      => array( 'label' => __( 'User', 'secupress' ),      'class' => '' ),
		);

		echo '<p class="logs-order">';

			echo '<span class="screen-reader-text">';
				printf(
					/* translators: 1 is "date", "criticity" or "user" ; 2 is "ascending" or "descending". */
					__( 'Current order: by %1$s, %2$s.', 'secupress' ),
					$orderbys[ $this->orderby ]['label'],
					( 'ASC' === $this->order ? __( 'ascending', 'secupress' ) : __( 'descending', 'secupress' ) )
				);
			echo "</span>\n";

			echo '<span>' . __( 'Order logs by:', 'secupress' ) . "</span>\n";

			echo "<span>\n";
				$orderbys[ $this->orderby ]['label'] .= $suffix[ $this->order ]['arrow'];
				$orderbys[ $this->orderby ]['class'] .= ' active-filter';

				foreach ( $orderbys as $orderby => $atts ) {
					echo ' <a class="button' . $atts['class'] . '" href="' . static::$page_url . $this->_get_order_params( $orderby, true ) . '">' . $atts['label'] . "</a>\n";
				}
			echo "</span>\n";

		echo "</p>\n";
	}


	/**
	 * Print a "Empty logs" button.
	 *
	 * @since 1.0
	 */
	protected static function _clear_logs_button() {
		$href = urlencode( secupress_admin_url( 'modules', 'logs' ) );
		$href = admin_url( 'admin-post.php?action=secupress_empty-logs&_wp_http_referer=' . $href );
		$href = wp_nonce_url( $href, 'secupress-empty-logs' );

		echo '<a class="button secupress-clear-logs" href="' . $href . '">' . __( 'Clear Logs', 'secupress' ) . "</a> <span class=\"spinner\"></span>\n";
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

		if ( $orderby !== static::$def_orderby ) {
			$params .= '&amp;' . static::ORDERBY_PARAM . '=' . $orderby;
		}

		if ( $orderby === $this->orderby ) {
			if ( $reverse_order && $this->order === static::$def_orders[ $orderby ] ) {
				$params .= '&amp;' . static::ORDER_PARAM . '=' . $reverse[ $this->order ];
			} elseif ( ! $reverse_order && $this->order !== static::$def_orders[ $orderby ] ) {
				$params .= '&amp;' . static::ORDER_PARAM . '=' . strtolower( $this->order );
			}
		}

		return $params;
	}


	/**
	 * Callback used to set the criticity parameter in a log array.
	 *
	 * @since 1.0
	 *
	 * @param (array) $log The log.
	 *
	 * @return (array) The log.
	 */
	public static function _set_criticity_callback( $log ) {
		$log['critic'] = SecuPress_Log::get_criticity_for( $log['type'], $log['code'] );
		return $log;
	}


	/**
	 * Callback used with `uasort()` to order the logs by ascending criticity.
	 *
	 * @since 1.0
	 *
	 * @param (array) $log_a The first log.
	 * @param (array) $log_b The second log.
	 *
	 * @return (int)
	 */
	public static function _order_by_criticity_asc_callback( $log_a, $log_b ) {
		$orders = array(
			'high'   => 3,
			'normal' => 2,
			'low'    => 1,
		);
		if ( $orders[ $log_a['critic'] ] === $orders[ $log_b['critic'] ] ) {
			return 0;
		}
		if ( $orders[ $log_a['critic'] ] > $orders[ $log_b['critic'] ] ) {
			return 1;
		}
		return -1;
	}


	/**
	 * Callback used with `uasort()` to order the logs by descending criticity.
	 *
	 * @since 1.0
	 *
	 * @param (array) $log_a The first log.
	 * @param (array) $log_b The second log.
	 *
	 * @return (int)
	 */
	public static function _order_by_criticity_desc_callback( $log_a, $log_b ) {
		$orders = array(
			'high'   => 3,
			'normal' => 2,
			'low'    => 1,
		);
		if ( $orders[ $log_a['critic'] ] === $orders[ $log_b['critic'] ] ) {
			return 0;
		}
		if ( $orders[ $log_a['critic'] ] > $orders[ $log_b['critic'] ] ) {
			return -1;
		}
		return 1;
	}


	/**
	 * Callback used with `uasort()` to order the logs by ascending user.
	 *
	 * @since 1.0
	 *
	 * @param (array) $log_a The first log.
	 * @param (array) $log_b The second log.
	 *
	 * @return (int)
	 */
	public static function _order_by_user_asc_callback( $log_a, $log_b ) {
		return strcasecmp( $log_a['user'], $log_b['user'] );
	}


	/**
	 * Callback used with `uasort()` to order the logs by descending user.
	 *
	 * @since 1.0
	 *
	 * @param (array) $log_a The first log.
	 * @param (array) $log_b The second log.
	 *
	 * @return (int)
	 */
	public static function _order_by_user_desc_callback( $log_a, $log_b ) {
		return strcasecmp( $log_b['user'], $log_a['user'] );
	}

}
