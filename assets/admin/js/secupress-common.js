(function($, d, w, undefined) {

	/**
	 * Tabs
	 * @author : Geoffrey
	 */
	
	$('.secupress-tabs').each( function(){

		var $tabs		= $(this),
			$content 	= $tabs.data('content') ? $( $tabs.data('content') ) : $tabs.next(),
			$tab_content= $content.find('.secupress-tab-content'),
			$current 	= $tabs.find('.secupress-current').lenght ? $tabs.find('.secupress-current') : $tabs.find('a:first'),

			set_current = function( $item ) {
				$item.closest('.secupress-tabs').find('a').removeClass('secupress-current').attr('aria-selected', false);
				$item.addClass('secupress-current').attr('aria-selected', true);
			},
			change_tab = function( $item ) {
				$tab_content.hide().attr('aria-hidden', true);
				$( '#' + $item.attr('aria-control') ).fadeIn(300).attr('aria-hidden', false);
			}

		$tab_content.hide();

		$tabs.find('a').on( 'click.secupress', function() {
			set_current( $(this) );
			change_tab( $(this) );
			return false;
		} );

		$current.trigger('click.secupress');

	} );

} )(jQuery, document, window);