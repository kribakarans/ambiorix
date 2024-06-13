(function (conndbview, $, undefined) {
    (function (service, $, undefined) {
        let init = false;
        
        service.updaterow = function(service, service_info) {
            var datatable = $('#ServiceTable').DataTable();
            let rownode = $('#' + service + '_row');
            var rows = datatable.rows(rownode).data();
            var addRow = {
                service: service,
                active: service_info.Active,
                nrconn: service_info.Connections.length,
                active_duration: service_info.CategoryActiveTime,
                total_duration: service_info.CategoryTotalActiveTime,
            }

            if(rows.length > 0) {
                datatable.row(rownode).data(addRow).draw();
            } else {
                rownode = datatable.row.add(addRow).draw().node();
                $(rownode).attr('id',service + '_row');
            } 
        }

        service.init = async function() {
            if(init) {
                return;
            }

            let service_table = await window.templates.load("service-table");

            $('body .content').append(service_table);

            $('#ServiceTable')
            .DataTable({
                dom: 'rt',
                columns: [
                    { data: 'service' },
                    { data: 'active'},
                    { data: 'nrconn' },
                    { data: 'active_duration' },
                    { data: 'total_duration' },
                ],

                "paging": false,
                "ordering": true,
                "info": false,

                order: [[3, 'Desc']],

                "language": {
                    "emptyTable": "No data available"
                },
            });

            init = true;
        }

        service.cleanup = function () {
            $('#ServiceContainer').remove();

            init = false;
        }

    } (conndbview.service = conndbview.service || {}, jQuery ));
}(window.conndbview = window.conndbview || {}, jQuery ));