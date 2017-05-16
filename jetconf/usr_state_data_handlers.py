from colorlog import error, warning as warn, info

from yangson.instance import InstanceRoute

from .helpers import JsonNodeT, PathFormat
from .handler_list import STATE_DATA_HANDLES, StateDataContainerHandler
from .data import BaseDatastore


# ---------- User-defined handlers follow ----------

# This handler will generate /example-jukebox:jukebox/library/artist-count node
class JukeboxExampleStateHandler(StateDataContainerHandler):
    def generate_node(self, node_ii: InstanceRoute, username: str, staging: bool) -> JsonNodeT:
        info("jukebox_example_handler, ii = {}".format(node_ii))
        artist_list_ii = self.ds.parse_ii("/example-jukebox:jukebox/library/artist", PathFormat.URL)
        jb_artists = self.ds.get_data_root().goto(artist_list_ii).value

        return len(jb_artists)


# This handler will generate /example-jukebox:jukebox/library/album-count node
class JukeboxExampleStateHandlerAc(StateDataContainerHandler):
    def generate_node(self, node_ii: InstanceRoute, username: str, staging: bool) -> JsonNodeT:
        info("jukebox_example_handler_ac, ii = {}".format(node_ii))
        artist_list_ii = self.ds.parse_ii("/example-jukebox:jukebox/library/artist", PathFormat.URL)
        jb_artists = self.ds.get_data_root().goto(artist_list_ii).value
        album_count = 0

        for artist in jb_artists:
            album_list = artist.get("album", [])
            album_count += len(album_list)

        return album_count


# This handler will generate /example-jukebox:jukebox/library/song-count node
class JukeboxExampleStateHandlerSc(StateDataContainerHandler):
    def generate_node(self, node_ii: InstanceRoute, username: str, staging: bool) -> JsonNodeT:
        info("jukebox_example_handler_sc, ii = {}".format(node_ii))
        artist_list_ii = self.ds.parse_ii("/example-jukebox:jukebox/library/artist", PathFormat.URL)
        jb_artists = self.ds.get_data_root().goto(artist_list_ii).value
        song_count = 0

        for artist in jb_artists:
            album_list = artist.get("album", [])
            for album in album_list:
                song_list = album.get("song", [])
                song_count += len(song_list)

        return song_count


# Instantiate state data handlers
def register_state_handlers(ds: BaseDatastore):
    esh = JukeboxExampleStateHandler(ds, "/example-jukebox:jukebox/library/artist-count")
    esh_ac = JukeboxExampleStateHandlerAc(ds, "/example-jukebox:jukebox/library/album-count")
    esh_sc = JukeboxExampleStateHandlerSc(ds, "/example-jukebox:jukebox/library/song-count")
    STATE_DATA_HANDLES.register(esh)
    STATE_DATA_HANDLES.register(esh_ac)
    STATE_DATA_HANDLES.register(esh_sc)
