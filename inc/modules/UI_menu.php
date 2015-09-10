<?php
defined( 'ABSPATH' ) or die( 'Cheatin&#8217; uh?' );

secupress_admin_heading( __( 'Modules', 'secupress' ) );
?>
<h2 class="nav-tab-wrapper hide-if-no-js">
	<?php
	foreach ( $secupress_modules as $key => $secupress_module ) {
		$active_class = $modulenow == $key ? ' nav-tab-active' : '';
		$icon = isset( $secupress_module['dashicon'] ) ?  $secupress_module['dashicon'] : 'admin-generic';
	?>
		<a href="<?php echo secupress_admin_url( 'modules', $key ); ?>" class="nav-tab<?php echo $active_class; ?> active_module" style="outline: 0px;">
			<span class="dashicons dashicons-<?php echo $icon; ?>"></span> <?php echo $secupress_module['title']; ?>
		</a>
	<?php
	}
	?>
</h2>