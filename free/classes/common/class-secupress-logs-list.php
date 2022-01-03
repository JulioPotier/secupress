<?php
defined( 'ABSPATH' ) or die( 'Something went wrong.' );

/**
 * General Logs list class.
 *
 * @package SecuPress
 * @since 1.0
 */
class SecuPress_Logs_List extends SecuPress_Singleton {

	const VERSION = '1.0';
	/**
	 * The reference to the *Singleton* instance of this class.
	 *
	 * @var (object)
	 */
	protected static $_instance;

	/**
	 * Logs instance.
	 *
	 * @var (object)
	 */
	private $logs_instance;

	/**
	 * Current Log type.
	 *
	 * @var (string)
	 */
	private $log_type;

	/**
	 * Current Post type.
	 *
	 * @var (string)
	 */
	private $post_type;

	/**
	 * Log class name.
	 *
	 * @var (string)
	 */
	private $log_classname;

	/**
	 * ID of the Log currently being displayed.
	 *
	 * @var (int)
	 */
	private $current_log_id = 0;


	/** Init ==================================================================================== */

	/**
	 * Set the values.
	 *
	 * @since 1.0
	 */
	protected function _init() {
		$log_types = SecuPress_Logs::get_log_types();

		// Get the Log type.
		$this->log_type      = ! empty( $_GET['tab'] ) ? $_GET['tab'] : '';
		$this->log_type      = $this->log_type && isset( $log_types[ $this->log_type ] ) ? $this->log_type : key( $log_types );

		// Get the Logs instance.
		$logs_classname      = $log_types[ $this->log_type ]['classname'];
		$this->logs_instance = $logs_classname::get_instance();

		// Get the Log class.
		$this->log_classname = $logs_classname::maybe_include_log_class();

		// Get the Post type.
		$this->post_type     = $log_types[ $this->log_type ]['post_type'];
	}


	/** Private methods ========================================================================= */

	/**
	 * Prepare the list.
	 *
	 * @since 1.0
	 */
	public function prepare_list() {
		global $wp_query, $wp_list_table;

		secupress_require_class( 'Logs', 'List_Table' );

		// Instantiate the list.
		$wp_list_table = new SecuPress_Logs_List_Table( array( 'screen' => convert_to_screen( $this->post_type ) ) ); // WPCS: override ok.

		// Query the Logs.
		$wp_list_table->prepare_items();

		/**
		 * Display a Log content.
		 * If the Log doesn't exist, remove the "log" parameter and redirect.
		 */
		if ( ! empty( $_GET['log'] ) ) {
			$log_classname        = $this->log_classname;
			$this->current_log_id = $log_classname::log_exists( $_GET['log'], $this->log_type );

			if ( ! $this->current_log_id ) {
				$sendback = $this->paged_page_url();
				wp_redirect( esc_url_raw( $sendback ) );
				exit();
			}
		}

		// Screen options and stuff.
		$current_screen = get_current_screen();

		if ( method_exists( $current_screen, 'set_screen_reader_content' ) ) {

			$post_type_object = get_post_type_object( $this->post_type );

			$current_screen->set_screen_reader_content( array(
				'heading_views'      => $post_type_object->labels->filter_items_list,
				'heading_pagination' => $post_type_object->labels->items_list_navigation,
				'heading_list'       => $post_type_object->labels->items_list,
			) );
		}

		add_screen_option( 'per_page', array( 'default' => 20, 'option' => 'edit_' . $this->post_type . '_per_page' ) );
	}


	/**
	 * Display the list.
	 *
	 * @since 1.0
	 */
	public function display_list() {
		global $wp_list_table;
		?>
		<div class="wrap">
			<?php
			// The page title.
			$log_types  = SecuPress_Logs::get_log_types();
			$head_title = get_post_type_object( $log_types[ $this->log_type ]['post_type'] )->label;

			secupress_admin_heading( $head_title );
			secupress_settings_heading( array(
				'title'    => $head_title,
				'subtitle' => __( 'Monitor everything', 'secupress' ),
			) );
			?>

			<div class="secupress-logs-list-wrapper">
				<?php
				// Messages.
				settings_errors();

				// Maybe display a Log infos.
				$this->display_current_log();
				?>

				<div class="secupress-logs-list">

					<?php $wp_list_table->views(); ?>

					<form id="posts-filter" method="get" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>">

						<?php $wp_list_table->display(); ?>

					</form>
				</div>
			</div>
		</div>
		<?php
	}


	/**
	 * The page title, maybe with tabs.
	 *
	 * @since 1.0
	 */
	public function screen_title_or_tabs() {
		global $title, $wp_list_table;

		$title_tag = secupress_wp_version_is( '4.3-alpha' ) ? 'h1' : 'h2';
		$log_types = SecuPress_Logs::get_log_types();

		// No tabs, somebody messed it up. Fallback.
		if ( ! $log_types || ! is_array( $log_types ) ) {
			echo "<$title_tag>$title</$title_tag>\n";
			return;
		}

		// Only 1 tab, no need to go further.
		if ( 1 === count( $log_types ) ) {
			echo "<$title_tag>" . get_post_type_object( $log_types[ $this->log_type ]['post_type'] )->label . "</$title_tag>\n";
			return;
		}

		$i        = 0;
		$page_url = secupress_admin_url( 'logs' );

		echo "<$title_tag class=\"nav-tab-wrapper\">";

		foreach ( $log_types as $log_type => $atts ) {
			$current_url = $i ? add_query_arg( 'tab', $log_type, $page_url ) : $page_url;
			$label       = get_post_type_object( $atts['post_type'] )->label;

			echo ( $i ? '<span class="screen-reader-text">, </span>' : '' ) . '<a class="nav-tab' . ( $log_type === $this->log_type ? ' nav-tab-active' : '' ) . '" href="' . esc_url( $current_url ) . '">' . $label . '</a>';
			++$i;
		}

		echo "</$title_tag>\n";
	}


	/**
	 * Maybe display the current Log infos.
	 *
	 * @since 1.0
	 *
	 * @return True if a Log is displayed. False otherwize.
	 */
	protected function display_current_log() {
		global $avail_post_stati;

		$log_types      = SecuPress_Logs::get_log_types();
		$has_tabs_class = count( $log_types ) > 1 ? ' secupress-has-log-tabs' : ' secupress-has-no-log-tabs';

		if ( ! $this->current_log_id ) {
			echo '<div class="secupress-log-content secupress-empty-log-content' . $has_tabs_class . '"><p>' . __( 'No logs selected', 'secupress' ) . "</p></div>\n";
			return false;
		}

		$log_classname = $this->log_classname;
		$log           = new $log_classname( $this->current_log_id );

		if ( ! $log ) {
			echo '<div class="secupress-log-content secupress-empty-log-content' . $has_tabs_class . '"><p>' . __( 'No logs selected', 'secupress' ) . "</p></div>\n";
			return false;
		}

		$page_url              = $this->page_url();
		$paged_page_url        = $this->paged_page_url();
		$user_raw              = $log->get_user( true );
		$delete_url            = $this->logs_instance->delete_log_url( $this->current_log_id, $page_url );
		$delete_by_ip_url      = $this->logs_instance->delete_logs_by_ip_url( $user_raw->user_ip, $page_url );
		$delete_by_user_id_url = $this->logs_instance->delete_logs_by_user_id_url( $user_raw->user_id, $page_url );
		$ban_ip_url            = wp_nonce_url( admin_url( 'admin-post.php?action=secupress-ban-ip&ip=' . urlencode( $user_raw->user_ip ) . '&_wp_http_referer=' . urlencode( esc_url_raw( $paged_page_url ) ) ), 'secupress-ban-ip' );

		if ( ! empty( $_GET['critic'] ) && in_array( $_GET['critic'], $avail_post_stati, true ) ) {
			$close_href        = add_query_arg( array( 'critic' => $_GET['critic'] ), $paged_page_url );
		} else {
			$close_href        = $paged_page_url;
		}

		// Add a class to the current Log row.
		add_filter( 'post_class', array( $this, 'add_current_log_class' ), 10, 3 );
		?>
		<div class="secupress-log-content<?php echo $has_tabs_class; ?>" data-logid="<?php echo $this->current_log_id; ?>">
			<div class="secupress-log-content-header secupress-section-primary">
				<div class="secupress-flex">
					<p class="secupress-log-title">
						<?php _e( 'Log Details', 'secupress' ); ?>
					</p>
					<p class="secupress-log-delete-actions">
						<a class="secupress-action-links secupress-delete-log" href="<?php echo esc_url( $delete_url ); ?>">
							<i class="secupress-icon-trash" aria-hidden="true"></i>
							<?php _e( 'Delete log', 'secupress' ); ?>
						</a>
						<span class="spinner secupress-inline-spinner"></span>

						<a class="secupress-action-links secupress-delete-logs-by-user_id" href="<?php echo esc_url( $delete_by_user_id_url ); ?>">
							<i class="secupress-icon-trash" aria-hidden="true"></i>
							<?php echo $user_raw->user_id ? __( 'Delete logs for this user', 'secupress' ) : __( 'Delete logs without user ID', 'secupress' ); ?>
						</a>
						<span class="spinner secupress-inline-spinner"></span>
					</p>
				</div>
				<div class="secupress-flex">
					<p class="secupress-log-user">
						<?php
						$referer = add_query_arg( 'log', $this->current_log_id, $paged_page_url );
						$filters = array(
							'user_ip'    => add_query_arg( 'user_ip', '%s', $page_url ),
							'user_id'    => add_query_arg( 'user_id', '%d', $page_url ),
							'user_login' => add_query_arg( 'user_login', '%s', $page_url ),
						);
						echo $log->get_user( false, $referer, $filters );
						?>
					</p>
					<p class="secupress-ip-handler">
						<?php if ( ! secupress_ip_is_whitelisted( $user_raw->user_ip ) && secupress_get_ip() !== $user_raw->user_ip ) { ?>
							<a class="secupress-action-links secupress-ban-ip" href="<?php echo esc_url( $ban_ip_url ); ?>">
								<i class="secupress-icon-times-circle" aria-hidden="true"></i>
								<?php _e( 'Ban this IP', 'secupress' ); ?>
							</a>
							<span class="spinner secupress-inline-spinner"></span>
						<?php } ?>

						<a class="secupress-action-links secupress-delete-logs-by-ip" href="<?php echo esc_url( $delete_by_ip_url ); ?>">
							<i class="secupress-icon-trash" aria-hidden="true"></i>
							<?php _e( 'Delete logs with this IP', 'secupress' ); ?>
						</a>
						<span class="spinner secupress-inline-spinner"></span>
					</p>
				</div>
				<a class="close" href="<?php echo esc_url( $close_href ); ?>">
					<i class="secupress-icon-squared-cross" aria-hidden="true"></i>
					<span class="screen-reader-text"><?php _e( 'Close' ); ?></span>
				</a>
			</div>
			<div class="secupress-log-content-message">
				<?php echo $log->get_message(); ?>
			</div>
		</div><!-- .secupress-log-content -->
		<?php
		return true;
	}


	/**
	 * Add a "current-log" class to the row of the Log currently being displayed.
	 *
	 * @since 1.0
	 *
	 * @param (array) $classes An array of post classes.
	 * @param (array) $class   An array of additional classes added to the post.
	 * @param (int)   $post_id The post ID.
	 *
	 * @return (array)
	 */
	public function add_current_log_class( $classes, $class, $post_id ) {
		if ( $post_id === $this->current_log_id ) {
			$classes[] = 'current-log';
		}
		return $classes;
	}


	/** Tools =================================================================================== */

	/**
	 * The page URL.
	 *
	 * @since 1.0
	 *
	 * @return (string)
	 */
	protected function page_url() {
		global $wp_list_table;
		return $wp_list_table->page_url();
	}


	/**
	 * The page URL, with the page number parameter.
	 *
	 * @since 1.0
	 *
	 * @return (string)
	 */
	protected function paged_page_url() {
		global $wp_list_table;
		return $wp_list_table->paged_page_url();
	}
}
