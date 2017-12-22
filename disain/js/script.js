
function toggleChevron(e) {
    $(e.target)
      .prev('.method-block')
      .find("i")
      .toggleClass('fa-chevron-up fa-chevron-down');
  }
  $('#accordion').on('hidden.bs.collapse', toggleChevron);
  $('#accordion').on('shown.bs.collapse', toggleChevron);
