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
	 * @var (object) The reference to the *Singleton* instance of this class.
	 */
	protected static $_instance;
	/**
	 * @var (object) Logs instance.
	 */
	private $logs_instance;
	/**
	 * @var (string) Current Log type.
	 */
	private $log_type;
	/**
	 * @var (string) Current Post type.
	 */
	private $post_type;
	/**
	 * @var (string) Log class name.
	 */
	private $log_classname;
	/**
	 * @var (int) ID of the Log currently being displayed.
	 */
	private $current_log_id = 0;


	// Init ========================================================================================

	/**
	 * Set the values.
	 *
	 * @since 1.0
	 */
	protected function _init() {
		$log_types = SecuPress_Logs::_get_log_types();

		// Get the Log type.
		$this->log_type      = ! empty( $_GET['tab'] ) ? $_GET['tab'] : '';
		$this->log_type      = $this->log_type && isset( $log_types[ $this->log_type ] ) ? $this->log_type : key( $log_types );

		// Get the Logs instance.
		$logs_classname      = $log_types[ $this->log_type ]['classname'];
		$this->logs_instance = $logs_classname::get_instance();

		// Get the Log class.
		$this->log_classname = $logs_classname::_maybe_include_log_class();

		// Get the Post type.
		$this->post_type     = $log_types[ $this->log_type ]['post_type'];
	}


	// Private methods =============================================================================

	/**
	 * Prepare the list.
	 *
	 * @since 1.0
	 */
	public function _prepare_list() {
		global $wp_query, $wp_list_table;

		secupress_require_class( 'Logs', 'List_Table' );

		// Instantiate the list.
		$wp_list_table = new SecuPress_Logs_List_Table( array( 'screen' => convert_to_screen( $this->post_type ) ) );

		// Query the Logs.
		$wp_list_table->prepare_items();

		/**
		 * Display a Log content.
		 * If the Log ID is not in the list we display, remove the "log" parameter and redirect.
		 */
		if ( ! empty( $_GET['log'] ) ) {
			$log_id = (int) $_GET['log'];

			if ( ! empty( $wp_query->posts ) ) {
				foreach ( $wp_query->posts as $post ) {
					if ( (int) $post->ID === $log_id ) {
						$this->current_log_id = $log_id;
						break;
					}
				}
			}

			if ( ! $this->current_log_id ) {
				$sendback = $this->_paged_page_url();
				wp_redirect( $sendback );
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
	public function _display_list() {
		global $wp_list_table;
		?>
		<div class="wrap">
			<?php
			// The page title.
			$this->_screen_title_or_tabs();
			?>

			<div class="secupress-logs-list-wrapper">
				<?php
				// Messages.
				settings_errors();

				// Maybe display a Log infos.
				$this->_display_current_log();
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
	public function _screen_title_or_tabs() {
		global $title, $wp_list_table;

		$title_tag = secupress_wp_version_is( '4.3-alpha' ) ? 'h1' : 'h2';
		$log_types = SecuPress_Logs::_get_log_types();

		// No tabs, somebody messed it up. Fallback.
		if ( ! $log_types || ! is_array( $log_types ) ) {
			echo "<$title_tag>$title</$title_tag>\n";
		}
		// Only 1 tab, no need to go further.
		elseif ( 1 === count( $log_types ) ) {
			echo "<$title_tag>" . get_post_type_object( $log_types[ $this->log_type ]['post_type'] )->label . "</$title_tag>\n";
		}
		else {
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
	}


	/**
	 * Maybe display the current Log infos.
	 *
	 * @since 1.0
	 *
	 * @return True if a Log is displayed. False otherwize.
	 */
	protected function _display_current_log() {
		if ( ! $this->current_log_id ) {
			echo '<div class="secupress-log-content secupress-empty-log-content"><p>' . __( 'No Logs selected', 'secupress' ) . "</p></div>\n";
			return false;
		}

		$log_classname = $this->log_classname;
		$log           = new $log_classname( $this->current_log_id );

		if ( ! $log ) {
			echo '<div class="secupress-log-content secupress-empty-log-content"><p>' . __( 'No Logs selected', 'secupress' ) . "</p></div>\n";
			return false;
		}

		$delete_url = $this->logs_instance->delete_log_url( $this->current_log_id, $this->_page_url() );

		// Add a class to the current Log row.
		add_filter( 'post_class', array( $this, '_add_current_log_class' ), 10, 3 );
		?>
		<div class="secupress-log-content" data-logid="<?php echo $this->current_log_id; ?>">
			<p class="log-header">

				<a class="secupress-delete-log" href="<?php echo esc_url( $delete_url ); ?>"><?php _e( 'Delete this Log', 'secupress' ); ?></a>
				<span class="spinner secupress-inline-spinner"></span>
				<a class="close" href="<?php echo esc_url( $this->_paged_page_url() ); ?>"><?php _e( 'Close' ); ?></a>

			</p>

			<p class="log-user">
				<?php echo $log->get_user( false, add_query_arg( 'log', $this->current_log_id, $this->_paged_page_url() ) ); ?>
			</p>

			<p class="log-message">
				<?php echo $log->get_message(); ?>
			</p>
		</div>
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
	public function _add_current_log_class( $classes, $class, $post_id ) {
		if ( $post_id === $this->current_log_id ) {
			$classes[] = 'current-log';
		}
		return $classes;
	}


	// Tools =======================================================================================

	/**
	 * The page URL.
	 *
	 * @since 1.0
	 *
	 * @return (string)
	 */
	protected function _page_url() {
		global $wp_list_table;
		return $wp_list_table->_page_url();
	}


	/**
	 * The page URL, with the page number parameter.
	 *
	 * @since 1.0
	 *
	 * @return (string)
	 */
	protected function _paged_page_url() {
		global $wp_list_table;
		return $wp_list_table->_paged_page_url();
	}
}
