<?php
/**
 * List Table API: SecuPress_Logs_List_Table class
 *
 * @package SecuPress
 * @since 1.0
 */

defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/**
 * Core class used to implement displaying Logs in a list table.
 *
 * @since 1.0
 * @see WP_List_Table
 */
class SecuPress_Logs_List_Table extends WP_List_Table {

	const VERSION = '1.0';
	/**
	 * Current Log.
	 *
	 * @var (object)
	 */
	protected $log = false;

	/**
	 * Logs class name.
	 *
	 * @var (string)
	 */
	protected $logs_classname;

	/**
	 * Log class name.
	 *
	 * @var (string)
	 */
	protected $log_classname;

	/**
	 * All available Log types.
	 *
	 * @var (array)
	 */
	protected $log_types;

	/**
	 * Current Log type.
	 *
	 * @var (string)
	 */
	protected $log_type;

	/**
	 * Default Log type.
	 *
	 * @var (string)
	 */
	protected $default_log_type;


	/**
	 * Constructor.
	 *
	 * @since 1.0
	 * @see WP_List_Table::__construct() for more information on default arguments.
	 *
	 * @param (array) $args An associative array of arguments.
	 */
	public function __construct( $args = array() ) {
		parent::__construct( array(
			'plural' => $args['screen']->post_type,
			'screen' => $args['screen'],
		) );
	}


	/**
	 * Get the current Log.
	 *
	 * @since 1.0
	 *
	 * return (object)
	 */
	public function get_log() {
		return $this->log;
	}


	/**
	 * Prepare all the things.
	 *
	 * @since 1.0
	 */
	public function prepare_items() {
		global $avail_post_stati, $wp_query, $per_page, $mode;

		// Set the infos we need.
		$post_type              = $this->screen->post_type;
		$this->log_types        = SecuPress_Logs::get_log_types();
		$this->default_log_type = key( $this->log_types );

		// Find the name of the class that handle this type of logs.
		foreach ( $this->log_types as $log_type => $atts ) {
			if ( $atts['post_type'] === $post_type ) {
				$this->log_type       = $log_type;
				$this->logs_classname = $atts['classname'];
				break;
			}
		}

		if ( empty( $this->logs_classname ) ) {
			return;
		}

		// Get the name of the class that handle this type of log.
		$logs_classname      = $this->logs_classname;
		$this->log_classname = $logs_classname::maybe_include_log_class();

		// Set some globals.
		$mode = 'list'; // WPCS: override ok.

		$per_page = $this->get_items_per_page( 'edit_' . $post_type . '_per_page' ); // WPCS: override ok.

		/** This filter is documented in wp-admin/includes/post.php */
		$per_page = apply_filters( 'edit_posts_per_page', $per_page, $post_type ); // WPCS: override ok.


		$avail_post_stati = get_available_post_statuses( $post_type ); // WPCS: override ok.

		// Get posts.
		$this->query();

		if ( $wp_query->found_posts || $this->get_pagenum() === 1 ) {
			$total_items = $wp_query->found_posts;
		} else {
			$post_counts = (array) wp_count_posts( $post_type );

			if ( ! empty( $_REQUEST['critic'] ) && in_array( $_REQUEST['critic'], $avail_post_stati, true ) ) {
				$total_items = $post_counts[ $_REQUEST['critic'] ];
			} else {
				$total_items = array_sum( $post_counts );
			}
		}

		$this->set_pagination_args( array(
			'total_items' => $total_items,
			'per_page'    => $per_page,
		) );
	}


	/**
	 * Query the Posts.
	 *
	 * @since 1.0
	 */
	protected function query() {
		global $avail_post_stati;

		// Prepare the query args.
		$args = array( 'post_type' => $this->screen->post_type );
		/**
		 * Filter the default query args used to display the logs.
		 *
		 * @since 1.0
		 *
		 * @param (array) $args An array containing at least the post type.
		 */
		$args = apply_filters( 'secupress.logs.logs_query_args', $args );

		// Criticity - Post Status.
		if ( ! empty( $_GET['critic'] ) && in_array( $_GET['critic'], $avail_post_stati, true ) ) {
			$args['post_status'] = $_GET['critic'];
		}

		// Order by.
		if ( ! empty( $_GET['orderby'] ) ) {
			switch ( $_GET['orderby'] ) {
				case 'date' :
					$args['orderby'] = 'date menu_order';
					break;
				case 'critic' :
					$args['orderby'] = 'post_status';
					break;
				default :
					$args['orderby'] = $_GET['orderby'];
			}
		}

		// Order.
		if ( empty( $args['order'] ) ) {
			$args['order'] = 'date menu_order' === $args['orderby'] ? 'DESC' : 'ASC';
		}
		$args['order'] = ! empty( $_GET['order'] ) ? $_GET['order'] : $args['order'];

		// Posts per page.
		$args['posts_per_page'] = (int) get_user_option( 'edit_' . $args['post_type'] . '_per_page' );

		if ( empty( $posts_per_page ) || $args['posts_per_page'] < 1 ) {
			$args['posts_per_page'] = 20;
		}

		// Metas.
		$filter_request = false;

		if ( ! empty( $_GET['user_ip'] ) ) {
			// User IP.
			$user_ip = urldecode( $_GET['user_ip'] );

			if ( secupress_ip_is_valid( $user_ip ) ) {
				$args['user_ip'] = $user_ip;
				$filter_request  = true;
			}
		}

		if ( ! empty( $_GET['user_id'] ) ) {
			// User ID.
			$user_id = (int) $_GET['user_id'];

			if ( $user_id ) {
				$args['user_id'] = $user_id;
				$filter_request  = true;
			}
		}

		if ( ! empty( $_GET['user_login'] ) ) {
			// User login.
			$args['user_login'] = esc_attr( $_GET['user_login'] );
			$filter_request     = true;
		}

		if ( $filter_request ) {
			add_action( 'parse_request', array( $this, 'filter_request' ) );
		}

		/** This filter is documented in wp-admin/includes/post.php */
		$args['posts_per_page'] = apply_filters( 'edit_' . $args['post_type'] . '_per_page', $args['posts_per_page'] );

		/** This filter is documented in wp-admin/includes/post.php */
		$args['posts_per_page'] = apply_filters( 'edit_posts_per_page', $args['posts_per_page'], $args['post_type'] );

		if ( isset( $_GET['log'] ) ) {
			// Custom query to be lighter.
			global $wpdb;
			$log_id           = (int) $_GET['log'];
			$main_post        = $wpdb->get_var( $wpdb->prepare( 'SELECT post_parent from ' . $wpdb->posts . ' WHERE post_type="%s" AND ID = %s ORDER BY ID DESC', $this->screen->post_type, $log_id ) );
			$main_post        = $main_post ? $main_post : $log_id;
			$children         = $wpdb->get_col( $wpdb->prepare( 'SELECT ID from ' . $wpdb->posts . ' WHERE post_type="%s" AND post_parent = %d ORDER BY ID ASC', $this->screen->post_type, $main_post ) );
			$ids              = array_filter( array_merge( [ $main_post ], $children ) );
			$args['post__in'] = $ids;
		}

		wp( $args );
	}


	/**
	 * Filter the main request to add custom query vars, like meta queries.
	 *
	 * @since 1.0
	 *
	 * @param (object) $wp `WP` object, passed by reference.
	 */
	public function filter_request( $wp ) {
		$wp->query_vars['meta_query'] = isset( $wp->query_vars['meta_query'] ) && is_array( $wp->query_vars['meta_query'] ) ? $wp->query_vars['meta_query'] : array();

		// User IP.
		if ( ! empty( $wp->extra_query_vars['user_ip'] ) ) {
			$wp->query_vars['meta_query'][] = array(
				'key'   => 'user_ip',
				'value' => $wp->extra_query_vars['user_ip'],
			);
		}

		// User ID.
		if ( ! empty( $wp->extra_query_vars['user_id'] ) ) {
			$wp->query_vars['meta_query'][] = array(
				'key'   => 'user_id',
				'value' => $wp->extra_query_vars['user_id'],
			);
		}

		// User login.
		if ( ! empty( $wp->extra_query_vars['user_login'] ) ) {
			$wp->query_vars['meta_query'][] = array(
				'key'   => 'user_login',
				'value' => $wp->extra_query_vars['user_login'],
			);
		}
	}


	/**
	 * Tell if we have Posts.
	 *
	 * @since 1.0
	 *
	 * @return (bool)
	 */
	public function has_items() {
		return have_posts();
	}


	/**
	 * Display a message telling no Posts are to be found.
	 *
	 * @since 1.0
	 */
	public function no_items() {
		echo get_post_type_object( $this->screen->post_type )->labels->not_found;
	}


	/**
	 * Determine if the current view is the "All" view.
	 *
	 * @since 1.0
	 *
	 * @return (bool) Whether the current view is the "All" view.
	 */
	protected function is_base_request() {
		$vars = $_GET;
		unset( $vars['paged'] );

		if ( empty( $vars ) ) {
			return true;
		} elseif ( 1 === count( $vars ) && ! empty( $vars['post_type'] ) ) {
			return $this->screen->post_type === $vars['post_type'];
		}

		return 1 === count( $vars );
	}


	/**
	 * Helper to create links to edit.php with params.
	 *
	 * @since 1.0
	 *
	 * @param (array)  $args  URL parameters for the link.
	 * @param (string) $label Link text.
	 * @param (string) $class Optional. Class attribute. Default empty string.
	 *
	 * @return (string) The formatted link string.
	 */
	protected function get_edit_link( $args, $label, $class = '' ) {
		$url = add_query_arg( $args, $this->page_url() );

		$class_html = '';
		if ( ! empty( $class ) ) {
			 $class_html = sprintf( ' class="%s"', esc_attr( $class ) );
		}

		return sprintf( '<a href="%s"%s>%s</a>', esc_url( $url ), $class_html, $label );
	}


	/**
	 * Get links allowing to filter the Posts by post status.
	 *
	 * @since 1.0
	 *
	 * @return (array)
	 */
	public function get_views() {
		global $avail_post_stati;

		$post_type       = $this->screen->post_type;
		$status_links    = array();
		$num_posts       = wp_count_posts( $post_type );
		$total_posts     = array_sum( (array) $num_posts );
		$class           = '';
		$current_user_id = get_current_user_id();

		if ( $this->is_base_request() || isset( $_REQUEST['all_posts'] ) ) {
			$class = 'current';
		}

		$all_inner_html = sprintf(
			_nx(
				'All <span class="count">(%s)</span>',
				'All <span class="count">(%s)</span>',
				$total_posts,
				'posts'
			),
			number_format_i18n( $total_posts )
		);

		$status_links['all'] = $this->get_edit_link( array(), $all_inner_html, $class );

		foreach ( get_post_stati( array(), 'objects' ) as $status ) {
			$class       = '';
			$status_name = $status->name;

			if ( ! in_array( $status_name, $avail_post_stati, true ) || empty( $num_posts->$status_name ) ) {
				continue;
			}

			if ( isset( $_REQUEST['critic'] ) && $status_name === $_REQUEST['critic'] ) {
				$class = 'current';
			}

			$status_args = array(
				'critic' => $status_name,
			);

			$status_label = sprintf(
				translate_nooped_plural( $status->label_count, $num_posts->$status_name ),
				number_format_i18n( $num_posts->$status_name )
			);

			$status_links[ $status_name ] = $this->get_edit_link( $status_args, $status_label, $class );
		}

		return $status_links;
	}


	/**
	 * Get bulk actions that will be displayed in the `<select>`.
	 *
	 * @since 1.0
	 *
	 * @return (array)
	 */
	public function get_bulk_actions() {
		return array(
			'secupress_bulk_delete-' . $this->log_type . '-logs' => __( 'Delete Permanently' ),
		);
	}


	/**
	 * Display "Delete All" and "Downlad All" buttons.
	 *
	 * @since 1.0
	 * @author Grégory Viguier (Geoffrey)
	 *
	 * @param (string) $which The position: "top" or "bottom".
	 */
	public function extra_tablenav( $which ) {

		if ( 'top' === $which ) {
			$logs_list = SecuPress_Logs_List::get_instance();
			$logs_list->screen_title_or_tabs();
		}
		?>
		<div class="secupress-quick-actions alignright actions">
			<?php
			if ( 'top' === $which && $this->has_items() ) {
				$logs_classname = $this->logs_classname;

				// "Downlad All" button.
				$href = $logs_classname::get_instance()->download_logs_url( $this->paged_page_url() );
				?>
				<a id="download_all" class="secupress-button secupress-button-primary secupress-button-mini apply secupress-download-logs" href="<?php echo esc_url( $href ); ?>">
					<span class="icon">
						<i class="secupress-icon-download" aria-hidden="true"></i>
					</span>
					<span class="text">
						<?php _e( 'Download All', 'secupress' ); ?>
					</span>
				</a>
				<span class="spinner secupress-inline-spinner"></span>

				<?php
				// "Delete All" button.
				$href = $logs_classname::get_instance()->delete_logs_url( $this->paged_page_url() );
				?>
				<a id="delete_all" class="secupress-button secupress-button-secondary secupress-button-mini apply secupress-clear-logs" href="<?php echo esc_url( $href ); ?>">
					<span class="icon">
						<i class="secupress-icon-trash" aria-hidden="true"></i>
					</span>
					<span class="text">
						<?php _e( 'Delete All', 'secupress' ); ?>
					</span>
				</a>
				<span class="spinner secupress-inline-spinner"></span>
				<?php
			}
			?>
		</div>
		<?php
		/** This action is documented in wp-admin/includes/class-wp-posts-list-table.php */
		do_action( 'manage_posts_extra_tablenav', $which );
	}


	/**
	 * Generate the table navigation above or below the table.
	 *
	 * @since 1.0
	 *
	 * @param (string) $which The position: "top" or "bottom".
	 */
	public function display_tablenav( $which ) {
		if ( 'top' === $which ) {
			wp_nonce_field( 'secupress-bulk-' . $this->log_type . '-logs', '_wpnonce', false );

			// Use a custom referer input, we don't want superfuous paramaters in the URL.
			echo '<input type="hidden" name="_wp_http_referer" value="' . esc_attr( $this->paged_page_url() ) . '" />';

			$args = wp_parse_url( $this->paged_page_url() );
			$args = ! empty( $args['query'] ) ? $args['query'] : '';

			if ( $args ) {
				// Display all other parameters ("page" is the most important).
				$args = explode( '&', $args );

				foreach ( $args as $arg ) {
					$arg = explode( '=', $arg );

					if ( isset( $arg[1] ) ) {
						echo '<input type="hidden" name="' . $arg[0] . '" value="' . $arg[1] . "\"/>\n";
					}
				}
			}
		}
		?>
		<div class="tablenav <?php echo esc_attr( $which ); ?>">

			<?php if ( 'top' === $which && $this->has_items() ) : ?>
			<div class="alignleft actions bulkactions">
				<?php $this->bulk_actions( $which ); ?>
			</div>
			<?php endif;
			$this->extra_tablenav( $which );
			$this->pagination( $which );
			?>

			<br class="clear" />
		</div>
	<?php
	}


	/**
	 * Get the classes to use on the `<table>`.
	 *
	 * @since 1.0
	 *
	 * @return (array)
	 */
	public function get_table_classes() {
		return array( 'widefat', 'fixed', 'striped', 'posts' );
	}


	/**
	 * Get the columns we are going to display.
	 *
	 * @since 1.0
	 *
	 * @return (array)
	 */
	public function get_columns() {
		$post_type = $this->screen->post_type;

		$posts_columns = array();

		$posts_columns['cb'] = '<input type="checkbox" />';

		/** Translators: manage posts column name */
		$posts_columns['title'] = _x( 'Title', 'column name' );

		if ( count( get_available_post_statuses( $post_type ) ) > 1 ) {
			$posts_columns['critic'] = __( 'priority', 'secupress' );
		}

		$posts_columns['date'] = __( 'Date' );

		/** This filter is documented in wp-admin/includes/class-wp-posts-list-table.php */
		$posts_columns = apply_filters( 'manage_posts_columns', $posts_columns, $post_type );

		/** This filter is documented in wp-admin/includes/class-wp-posts-list-table.php */
		return apply_filters( "manage_{$post_type}_posts_columns", $posts_columns );
	}


	/**
	 * Get the columns that can be sorted.
	 *
	 * @since 1.0
	 *
	 * @return (array)
	 */
	public function get_sortable_columns() {
		return array(
			'title' => 'title',
			'date'  => array( 'date', true ),
		);
	}


	/**
	 * Display the rows.
	 *
	 * @since 1.0
	 *
	 * @param (array) $posts An array of posts.
	 * @param (int)   $level Level of the post (level as in parent/child relation).
	 */
	public function display_rows( $posts = array(), $level = 0 ) {
		global $wp_query, $per_page;

		if ( empty( $posts ) ) {
			$posts = $wp_query->posts;
		}

		$this->_display_rows( $posts, $level );
	}


	/**
	 * Display the rows.
	 * The current Log is set here.
	 *
	 * @since 1.0
	 *
	 * @param (array) $posts An array of posts.
	 * @param (int)   $level Level of the post (level as in parent/child relation).
	 */
	private function _display_rows( $posts, $level = 0 ) {
		$log_classname = $this->log_classname;

		foreach ( $posts as $post ) {
			$this->log = new $log_classname( $post );
			$this->single_row( $post, $level );
		}

		$this->log = false;
	}


	/**
	 * Handles the checkbox column output.
	 *
	 * @since 1.0
	 * @since WP 4.3.0
	 *
	 * @param (object) $post The current WP_Post object.
	 */
	public function column_cb( $post ) {
		?>
		<label for="cb-select-<?php the_ID(); ?>">
			<span class="screen-reader-text">
				<?php printf( __( 'Select &#8220;%s&#8221;', 'secupress' ), strip_tags( $this->log->get_title( $post ) ) ); ?>
			</span>
			<input id="cb-select-<?php the_ID(); ?>" type="checkbox" name="post[]" value="<?php the_ID(); ?>" class="secupress-checkbox secupress-checkbox-mini" />
			<span class="label-text"></span>
		</label>
		<?php
	}


	/**
	 * Handles the title column output.
	 *
	 * @since 1.0
	 * @since WP 4.3.0
	 *
	 * @param (object) $post    The current WP_Post object.
	 * @param (string) $classes The cell classes.
	 * @param (string) $data    Cell data attributes.
	 * @param (string) $primary Name of the priramy column.
	 */
	protected function _column_title( $post, $classes, $data, $primary ) {
		echo '<td class="' . $classes . ' page-title" ', $data, '>';
			echo $this->column_title( $post );
			echo $this->handle_row_actions( $post, 'title', $primary );
		echo '</td>';
	}


	/**
	 * Handles the title column content.
	 *
	 * @since 1.0
	 * @since WP 4.3.0
	 *
	 * @param (object) $post The current WP_Post object.
	 */
	public function column_title( $post ) {
		global $avail_post_stati;

		$logs_classname = $this->logs_classname;
		$title          = $this->log->get_title( $post );
		$view_href      = array( 'log' => $post->ID );
		if ( ! empty( $_GET['critic'] ) && in_array( $_GET['critic'], $avail_post_stati, true ) ) {
			$view_href['critic'] = $_GET['critic'];
		}
		$view_href      = add_query_arg( $view_href, $this->paged_page_url() );
		$prefix         = 0 === $post->post_parent ? '' : ' — ';

		echo '<a class="secupress-view-log" href="' . esc_url( $view_href ) . '" title="' . esc_attr( sprintf( __( 'View &#8220;%s&#8221;', 'secupress' ), strip_tags( $title ) ) ) . '">';
			echo $prefix . $title;
		echo "</a>\n";

		if ( ! secupress_wp_version_is( '4.3.0' ) ) {
			echo $this->handle_row_actions( $post, 'title', $this->get_default_primary_column_name() );
		}
	}


	/**
	 * Handles the criticity column output.
	 *
	 * @since 1.0
	 *
	 * @param (object) $post The current WP_Post object.
	 */
	public function column_critic( $post ) {
		echo $this->log->get_criticity( 'icon' ) . ' <span class="secupress-log-crit-text">' . $this->log->get_criticity() . '</span>';
	}


	/**
	 * Handles the post date column output.
	 *
	 * @since 1.0
	 *
	 * @param (object) $post The current WP_Post object.
	 */
	public function column_date( $post ) {
		/** This filter is documented in wp-admin/includes/class-wp-posts-list-table.php */
		echo apply_filters( 'post_date_column_time', $this->log->get_time( __( '\<\b\>Y/m/d\<\/\b\> g:i:s a', 'secupress' ) ), $post, 'date', 'list' );
	}


	/**
	 * Handles the default column output.
	 *
	 * @since 1.0
	 *
	 * @param (object) $post        The current WP_Post object.
	 * @param (string) $column_name The current column name.
	 */
	public function column_default( $post, $column_name ) {
		/** This filter is documented in wp-admin/includes/class-wp-posts-list-table.php */
		do_action( 'manage_posts_custom_column', $column_name, $post->ID );

		/** This filter is documented in wp-admin/includes/class-wp-posts-list-table.php */
		do_action( "manage_{$post->post_type}_posts_custom_column", $column_name, $post->ID );
	}


	/**
	 * Display a row.
	 *
	 * @since 1.0
	 *
	 * @param (int|object) $post  The current post ID or WP_Post object.
	 * @param (int)        $level Level of the post (level as in parent/child relation).
	 */
	public function single_row( $post, $level = 0 ) {
		$global_post     = get_post();
		$post            = get_post( $post );
		$GLOBALS['post'] = $post; // WPCS: override ok.
		setup_postdata( $post );
		$class           = [ 'level' => 'level-' . ( (int) !! $post->post_parent ), 'hidden' => (int) !! $post->post_parent ? 'hid e-if-js' : '', 'parent' => 'parent-post-' . $post->post_parent ];
		if ( isset( $_GET['log'] ) ) {
			unset( $class['hidden'] );
		}
		$classes         = implode( ' ', get_post_class( $class, $post->ID ) );
		?>
		<tr id="post-<?php echo $post->ID; ?>" class="<?php echo $classes; ?>">
			<?php $this->single_row_columns( $post ); ?>
		</tr>
		<?php
		$GLOBALS['post'] = $global_post; // WPCS: override ok.
	}


	/**
	 * Get the name of the default primary column.
	 *
	 * @since 1.0
	 *
	 * @return (string) Name of the default primary column, in this case, 'title'.
	 */
	protected function get_default_primary_column_name() {
		return 'title';
	}


	/**
	 * Generate and display row action links.
	 *
	 * @since 1.0
	 *
	 * @param (object) $post        Current WP_Post object.
	 * @param (string) $column_name Current column name.
	 * @param (string) $primary     Primary column name.
	 *
	 * @return (string) Row actions output for posts.
	 */
	protected function handle_row_actions( $post, $column_name, $primary ) {
		global $avail_post_stati;

		if ( $primary !== $column_name ) {
			return '';
		}

		$logs_classname = $this->logs_classname;
		$delete_href    = $logs_classname::get_instance()->delete_log_url( $post->ID, $this->page_url() );
		$view_href      = array( 'log' => $post->ID );
		$critic         = null;
		if ( ! empty( $_GET['critic'] ) && in_array( $_GET['critic'], $avail_post_stati, true ) ) {
			$critic              = $_GET['critic'];
			$view_href['critic'] = $critic;
		}
		$view_href      = add_query_arg( $view_href, $this->paged_page_url() );

		$actions = [];
		if ( count( get_children( $post ) ) ) {
			$actions['delete'] = '<a class="secupress-delete-log submitdelete" href="' . esc_url( $delete_href ) . '" title="' . esc_attr__( 'Delete this item and its children permanently' ) . '">' . __( 'Delete Permanently with its children' ) . '</a> <span class="spinner secupress-inline-spinner"></span>';
		} else {
			$actions['delete'] = '<a class="secupress-delete-log submitdelete" href="' . esc_url( $delete_href ) . '" title="' . esc_attr__( 'Delete this item permanently' ) . '">' . __( 'Delete Permanently' ) . '</a> <span class="spinner secupress-inline-spinner"></span>';
		}
		$actions['view']   = '<a class="secupress-view-log" href="' . esc_url( $view_href ) . '" title="' . esc_attr__( 'View this log details', 'secupress' ) . '" tabindex="-1">' . __( 'View' ) . '</a>';

		/**
		* Filter the actions, only for secupress
		* @since 2.0 Do not use the WP hook name or we have too many useless actions
		* @param (array) $actions
		* @param (WP_Post) $post
		* @param (string) $criticity
		*/
		$actions = apply_filters( 'secupress.post_row_actions', $actions, $post, $critic );

		return $this->row_actions( $actions );
	}


	/**
	 * The page URL.
	 *
	 * @since 1.0
	 *
	 * @param (string) $log_type Type of Log.
	 *
	 * @return (string)
	 */
	public function page_url( $log_type = false ) {
		$href = secupress_admin_url( 'logs' );

		if ( ! $log_type ) {
			$log_type = $this->log_type;
		}

		if ( $this->default_log_type !== $log_type ) {
			$href = add_query_arg( 'tab', $log_type, $href );
		}

		return $href;
	}


	/**
	 * The page URL, with the page number parameter.
	 *
	 * @since 1.0
	 *
	 * @return (string)
	 */
	public function paged_page_url() {
		$page_url = $this->page_url();
		$pagenum  = $this->get_pagenum();

		if ( $pagenum > 1 ) {
			$page_url = add_query_arg( 'paged', $pagenum, $page_url );
		}

		return $page_url;
	}
}
