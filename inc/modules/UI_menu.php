<?php
defined( 'ABSPATH' ) or	die( 'Cheatin&#8217; uh?' );
?>
<h1><?php _e( '<h1>Modules</h1>', 'secupress' ); ?></h1>
<h2 class="nav-tab-wrapper hide-if-no-js">
		<?php
		foreach ( $secupress_modules as $key => $secupress_module ) {
			$active_class = $modulenow == $key ? ' nav-tab-active' : '';
			$active_module = secupress_is_module_active( $key ) ? ' active-module' : '';
			$icon = isset( $secupress_module['dashicon'] ) ?  $secupress_module['dashicon'] : 'admin-generic';
		?>
			<a href="<?php echo secupress_admin_url( 'modules', $key ); ?>" class="nav-tab<?php echo $active_class; ?><?php echo $active_module; ?>" style="outline: 0px;">
				<span class="dashicons dashicons-<?php echo $icon; ?>"></span> <?php echo $secupress_module['title']; ?>
			</a>
		<?php
		}
		?>
</h2>