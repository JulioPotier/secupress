<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

/**
 * Modules settings class.
 *
 * @package SecuPress
 * @subpackage SecuPress_Settings
 * @since 1.0
 */

class SecuPress_Settings_Modules extends SecuPress_Settings {

	const VERSION = '1.0';

	/**
	 * @var Singleton The reference to *Singleton* instance of this class
	 */
	protected static $_instance;


	public function print_page() {
		?>
		<div class="wrap">
			<?php secupress_admin_heading( __( 'Modules', 'secupress' ) ); ?>

			<div class="secupress-wrapper">

				<h2 class="nav-tab-wrapper hide-if-no-js">
					<?php $this->print_tabs(); ?>
				</h2>

				<div id="tab_content">
					<?php $this->print_current_module(); ?>
				</div>

			</div>

		</div>
		<?php
	}


	protected function print_tabs() {
		foreach ( static::get_modules() as $key => $module ) {
			$class = $this->get_current_module() === $key  ? ' nav-tab-active'    : '';
			$icon  = isset( $module['dashicon'] )          ?  $module['dashicon'] : 'admin-generic';
			?>
			<a href="<?php echo secupress_admin_url( 'modules', $key ); ?>" class="nav-tab<?php echo $class; ?> active_module">
				<span class="dashicons dashicons-<?php echo $icon; ?>" aria-hidden="true"></span> <?php echo $module['title']; ?>
			</a>
			<?php
		}
	}


	protected function print_current_module() {
		settings_errors();

		// No module.
		if ( 'welcome' === $this->get_current_module() ) {
			?>
			<div class="secublock">
				<?php $this->load_module_settings(); ?>
			</div>
			<?php
			return;
		}

		?>
		<div class="secublock">
			<?php
			$this->print_module_title();
			$this->print_module_description();
			?>
		</div>

		<form id="secupress-module-form-settings" method="post" action="<?php echo admin_url( 'options.php' ); ?>">

			<div id="block-advanced_options" data-module="<?php echo $this->get_current_module(); ?>">
				<?php $this->load_module_settings(); ?>
			</div>

			<?php
			$this->print_module_reset_box();

			settings_fields( 'secupress_' . $this->get_current_module() . '_settings' );
			?>

		</form>
		<?php
	}


	protected function print_module_reset_box() {
		//// todo save settings with history
		$this->set_current_section( 'reset' );
		$this->set_section_description( __( 'If you need to reset this module\'s settings to the default ones, you just have to do it here, we will set the best for your site.', 'secupress' ) );
		$this->add_section( __( 'Module settings', 'secupress' ) );

		$this->set_current_plugin( 'reset' );

		$this->add_field(
			__( 'Reset settings?', 'secupress' ),
			array(
				'name'        => 'reset',
				'field_type'  => 'field_button',
			),
			array(
				'button'      => array(
					'url'          => wp_nonce_url( admin_url( 'admin-post.php?action=secupress_reset_settings&module=' . $this->get_current_module() ), 'secupress_reset_' . $this->get_current_module() ),
					'button_label' => sprintf( __( 'Reset the %s\'s settings.', 'secupress' ), $this->get_module_title() ),
				),
			)
		);

		$this->do_sections( false );
	}
}
