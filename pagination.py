from rest_framework.pagination import PageNumberPagination

class Pagination(PageNumberPagination):
    """
    """
    def paginate_queryset(self, queryset, request, view=None):
        self.page_size_query_param= 'page_size'
        return super(Pagination, self).paginate_queryset(queryset, request, view)