"""Deterministic, owned-only private inputs for the six formal T40 cases.

The seed is an immutable canonical document rather than a runtime dependency on
``tests`` or ``labs``.  Every emitted document is revalidated against the real
FaultLoom arm schema and parser before it leaves this module.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
import zlib
from datetime import UTC, datetime, timedelta

from faultloom.context import checkpoint_binding_tag_for
from faultloom.model_utility_proxy_models import (
    FAULTLOOM_UTILITY_V1_MODEL_DIGEST,
    FAULTLOOM_UTILITY_V1_RUNTIME_DIGEST,
)
from faultloom.t40_arm_runtime import (
    T40ArmPolicy,
    T40ArmRequest,
    T40ResourceBudget,
    canonical_json_bytes,
)
from faultloom.t40_faultloom_arm import (
    T40FaultLoomPrivateInput,
    _parse_private,
    faultloom_implementation_digest,
)

_MIN_SLOT = 1
_MAX_SLOT = 6
_VERIFY_AT = datetime(2030, 1, 2, 3, 5, 5, 678901, tzinfo=UTC)
_SEED_SHA256 = "abeccbc5aaa876828efb2d38d6ac9a049423a494ea59198a29d03dea9fffe13d"

# This compressed representation keeps a large, closed object graph auditable
# through the public schema while avoiding any runtime fixture import.  The seed
# is never returned directly: slot ownership bindings are applied and the result
# is parsed again through the production arm contract.
_SEED_ZLIB_B64 = """
eNrtfWlz48iV4F/hcvfDeENi5Q1AEd6Innat3Q57e8buscOermDkKcFFEmyAVJXcUf99Xx4AAd4sSdXqtmRHF4FM5PXuly9f/jjW1WJlP67GNz+OZ+W9Hd84OWvs1XhZV/elsbUvkHq1lrNps5DL5q6CumNXw2elra8JougaYfj/+Kpta/qhXJjqw/iGI/jbfj21H6G98c2qXsdu5svV1JS3tvENN3eScHGDH/k37lqu7m19Z6XZ221XuKre20UzvqFkM/NpaWBA7dNk5Qd4Na7tD2v4Zc1UzkrZ9NbCF67h19xOodmmrBZQmN5c4wmaIKjRruFwOKH78p9tn93jcHlXVQVA0Hd2LncWjDzyb/zJT21Vl/YeIK0AUuXidvrePkzv7EfoJiOCZwz+W8C/QmChiRFcWJHB7wx+haeMEUMxlCioVWT54/7nl0tXSzuVC31X1bDW/w24uF7B73L1sLMEAhlTUMYFYbnNC4wKbZ10ubIwVick5ZppzQh1lFJNUI40di53QmFnqPQrfFvLxSrCIPyc+JfzclHO1/OpXVb6bnyTAYas1azUfnUCdcxu/YDu5vDVW0M4xwV85ZcuNGTjq5s0Si5YxqXMOBOUZUwjknPjuFGOKC1VRo0UHFOe57SwhcoylmNFrFQYZRnK9XjY/fgr8fZ399P/+PbtH5jR/w/9jaP7r+Z/de/xP75Wy//E7nfm4bd///ff/+WP6jasZ8CeDX6iCWDm+NOnd1C2kiubyB04wfTuYVmt7mxj48J7Kq6lKaEQMMN6olhoqP/f8KmurQwk4cHR4Sz5DtEbxG4Qn4gsLxD+O4ygbbVs4vJsnieRaq2nsLIpVxYqNLF9T4R2IWN/Y2Xv5H1Z1eN3geJiO/AjNHBghml6c7vwQ/xW/cPq1Sjh0j/lCqqOTOkcfDVSD6OV72w1SV+tPZXHRfFv1stlVW8vAqyPbJ6eKi9a2nY4Ce/SU1iVSjW2vg/zTKvafwVV/FJa4ycJNbanQR/5Nz4fTh4R10tz3pR9ZWhGv19W5WK1B3UDkoXZDtAMPntWNqLvZLmYAgdZ3sVJhxfX4cUkVmgH3Za3z7H4fJjfVsCut6dgNHKI5gwrThmRCGFkCdZIMqsIYS7Pi0wzjKkWBVYSOLV/RAZL5ZxBCtr1uLPyy9ObRfuuN5Fy7mnBM82FvZVh7WvbrGerdt3b13HVlzbKlYRnqU58mqTCUG8mF89BTLXVMIWObmGsrnkl3icl3hoKQGACkNXa3NqOKiuvXuVBG2xW03mp62q9KFdN0hKhwKzrOMfGgqzx86Th/bwydtZpaDjVPjSEvhqj13XT6g3xt6e18CNi78LYj8MFvw7vjsmRDwDRei7r934sny4TQUGb2egRMFEY7AYLl+t6WTUgTsbVh4U1o5bgjrW5rksP69DSzZs3MIY3HZ36VuoAlcZrrUFS4SDT1MxOBxPxcq12EvCvR/DpVY/e14v3C2h1Wq1XugJFdy8hp0oeLT9U9Xs3A6W/12r7rmv204AhtrrnSt569WAu9XWrOlmFgHchgbhwGhMuKSqAUVNjqLIOayY15sDUcmtYBpzNCpoJRp0URa6N8VS2uJW3QQtIYO+ew/Q8N4W3f7JqXc7M6P9K4GR/qKr56B6We/QBlDyYOPwLCwxDHHVCZBJ1R5hhA5qZV5h+jDzf/7BABhG+/lerFN5G2g6v3sOUPdADUVsz5AZhZXv8wEOzWtctp1gAdUSsW88BmF4lfNvi8qxcvAc06jELb0XIGsiy9zEJGHJEWvlaaQLDYb2LZVsDCa/SlJp10LQGw/s24HZb8unqjGbJVrMgY8ISDNr9Wi7gx6gr87MaEutGrP0s4bJH/v6CQJOYzc8SMruM8hcEmJZf/ywhsyNsfkGg+XRE/+5sdj1bJ43huzs7amuNgjVfzUYfZDPy0gymAL/sxyVMwppJH2yvSvKTK8l+nesyqCHPMJITLpZdS83j5cZOC2ZSVZvzQHKZbRA0c2j4vrQfEm005S0Q0HSgG4MqLB9mlTSB53T6MixbCYPeHRbftYv3efLKplmfOSt7X+mITICdjZ/HYj2bxQLgQ52b/LAZctgKgAnL1bq2h52HF0z0Of2MEQa7znlogSKeceoYfK5zZBDLFM6MZtjazFnHGMVKOoldrjhjOGecSGqwIczZ6JxfVbqa7VmejRHUR4lj69nZNtlgccf/xan5qrnL/vy3t/lDVa///Ifv2J++m13Xf/3b3Vd/ePjGfDP91pK/f8yqtzn75tsf6Ez+8NH8XuAP5v3vpsu//m3VoD+qt+W/46+mzdd/efh4x2+//mrcoexp/5Rn0TDg0pUJmfxewO5HfPCRX/iVvpvey7qUya1l5HIVhd7gKULelR/9jCf36xnYe962m/Q+AAYrwaLyLrVps7LL5EaPfFDPZOO9m410dgpAUR44qayVebDqoHbq6d1qtYy4GWTE1DrnJZ4XXxIE82L2MAIuMyphDKtRNGB1lGFeYoX9kTv5T1mb1J93rVswoPzzb99+1+dMSTr57Re/FNBSDYaXjZKq6XUTO9iDqy21/rAGQjLtPssR57BdJlUOfk388K5T216i/6ut1nHmtrNc1dIvgZxdK7kIHocXsGR3djZ7yRgWxvcCFgr4gpya9Xz5ghcrDG/PWoEeDw21GzNfYrEGHb7Y5eqNMmyRzKxcrJfT4FUHbd67eOKrSRzBNegadnW2zs+F4BrkOqgAzmsBuADpzouMFzYDVcKhHCOiUCYx1BQFsVRmVBLNSKExysUZOv8RZX8j2ia9bcGTBsD+z/YaBWn1+4ptAOR1ksjXM6lO6/cB2dIIvLu1w7uj2DYqGzD5QJwvgu3cbcO0MRRDR1B6O4mO3l0UDKtwHhL6XRep3yeNwjs+Z1U1n3ywav+u7OBdGIC57jXVK4ygCFP1MRSdV3sEaslgDCNZ21GIt/ALCvMP0NHl0h7Uc2LxMCzjCEqFJZjCgoA9MX4TxvSmI8JYGOjjx84kTyiQniZhuNebT9pardfDtzjtig8SbN9vEX/vxbC4DZ2qxS1pOVveybDL8ZnoedU5MWCWHXoN0KpDp1NNtM6v8LD5KhW2awKmrlxV9bQH2WlvZ+PYJM9dJ7DwGu8I8cYusPvGfysN9Aa2VfL1pMc01a//8jbF1qAQWiMDcXrDNM51Ci1GT9cYT8jko0fFedDKSwMTsYCKhxTv2M11qD3eCl2AYdSr0gG/2d2z5RnVFjinKrLMCls47jQpLHcFUjxTYD8ZlyFDiZPIEGqLvJACIeCt2nKcn829Nc0xplnOKZhtxlEL/1KBrNMZlhYRJywCUzHPjBNYKKNEkVOGwNiDUq30Y7l3XJ9J1dyfw7R7tZ+JVx+xK/W6jrx3Pi+7vvp8IXGFOJctVgDvgspyCOBIG6coy0EwCZ1lhSu4wo4ShiUIV1EwiQjOEWKSEZRTwVEheA7/xVZplJOzAZ67AmuXgXgWYItbSZxyWDEAOFPYGK1zhpGkChHEC8CCAhUgrQvFsoJwLeUTAXxxby4AuK/9cgEe5zIEuH93FOACE0xZoUiBiBRCKaqY82SHFCFE5UKh3LrMmSxjRjMjmCPOe0xy4AYRDucB3BhhAOI5zyUTQLuCYOWoAxyAPpHUhWWFVNQ5bA0QtdEUqL8AhU0QijTPnwjgwPZMVV8A8/TBywV7N6Mh5NPro8AvNGMcFhw0Zk7z3DHlYLElwRnJKc64KpzQGgnrcgGQI4AFVDqRK5xjhpw4G/jApnOJKGVaOEoRB0aCQZwo0Muz3IJxybHmVDsrjGHCcuAKpiAFU7RgKM/EEwG/tmBhNHa6qFb2AhQYfPZyEWFrdkN0GBQeRQpqWa6KIkfCSCkwMtZwbBihlBBsEHOMAutnEoQCIiAAGBHYqSInxBBZKHM2UrCcIqoJaBd5BjyfOh8AhnLAACwKBWxeAhJqSQtunSWYaQwMgRcFaBgchJR9IqTYXuDz8WL7y58cNcbyzL/xXgTaXYkhDm2XHxmcL3IlaKv1sk5RkPDREtRsvysog7+5s+eujZ1X1135ePDpQSur3/xVt7V7FBWO737MIqoq6YN+auh4YbyH3MdnJddjH6/DlPbtPWpqtSJMSQtMzBGQXRL4KeMFB/oA3VUDWRnEucqdQQUIWC2wMogQahQ1j1Rsjq/TxB8rsGdIv/OaeQ58vxonZOuGegJoB/EjFm+mPDCi4JNoQl2NP9jy9m41VX4PgoDl5ZnjY3EAVCXFQF3NlDDWaiSNwsDLcmNBsS0UzjQHtdmAfqUBLxjLBMYMVCwF4lYi96w40AWqPxYLBhHvz4YHveE+EhN6LZ2DC/RpcMExDVYtYQUoNKD+IOejmfOcKUGRUJRaS0C/JhTsIQTaEZjY1hqwbDHoxTxD/FlxoVHV/NF4EBp5VhxIw3wk/FMr58DeR/96EXaWq6fdGw27oEmraoZ+ldBA+zTp4mrONJU10USCBKHWUAuKD7I5MJActKOcSuAkQoGtjECGaArqNWCOoALlnGdaAQd6pG8kTG0z5BOoMqj9TPoQQNj7M72XOZybMdaN/LbJv/Xco1ejzoP3q5vvFyP4+5+jcpH6uOkCmEZSa9s03sEdP7hW1Xph2i98yHfph3+zaW/06193n0+6t+0XTbl432se1Jv362VbGNqW9UPb2mhVr5tV9zpWi452+GdZNeXK65mxkamr6mn87tBMv/cb6y3NdMFbh6hmQyEnFrNdwUMjG9SFMQzMiyHqQ0euvD0b9R2mXKKcUMxzh5DQjGc5WIRCZgYpVBSUSY2gjrLeacWtBsOFaG2wLCR88BSo3w35LNRPtb8Q6ifQp+j0X/sduQ0GdAO/DAO22gyi7hhI0xHUMyPzjLaI2SzLjLcYmXUUrECHJEGZcww044LrXGsCLMwWxIAANMwUPjDISanypwBoGvBZ4Ax1vxAwdV01TaLwabtZ92uG6AakaeiXAXR/u6DqHoOqXJZnA1VpRbktpM14ziSyFqg1M5kQBRaMA1UyMN9tLgyxKMt1zozkXjNmBsCniuIpgBrHexZMfdUvBNLfvv1uNNjRG13/nxFAdAS8fOTDH+vEvTcghtFNz9F594J6b38B0u/OBaYQghEkM+CxQH3MYZZ7eBQYSy2dsoQrzTKXE15gRsGO5RxKueWUU2lp9uT66jLtWV2upMYvnxXUtY27h8HDFn9eh5JwkCs1NtV3Xtc8qJ92FcdtlJ2xs5U8WL9dkXNwY98AN8XxZJqE8alylk6g+PND08HeegMr3LhyE/OxceUsfZDGYrUp8CLnxNdnar05AhnuRUFuKM4KCzimMu5EBvYzl6AI4FwVnpdoq7CyioMxxTJcIG5NxtiT4+FgnT4HHQcNPBdW2hBnegICEcnS0fqxVE30uvUH6MOZyvmREIfBYpyDiT7AwYufqmkHcjQe2c7i3vfxLfKOwtpo0hah2uDSDW88S3sdBKYetifVzJ8JvhrH0/k+asAf0fO+Ahh3uehCXabxFENHHl3TMe5m2h1IuYg0BBEILEHBtM0oM7kUStDMeed7kQsmMVIyk0AyGfwrsCTSUWUR8GcgJmsfuZuSlnyiZlK/B3Pp42li2P3kmdB/EOEzhV8eLEfj1D55IM7tIr1MoI3ROGcrtQhrRwysPBLYugzYk1UKgcDkVOdcuEJZTaFMgIQkXIvMeMcw5zrTudP0aeCxwcozodF+8EywmKWzCv5rH8TUvPHEX68my6McI9HiD2sbDhztkuv/+tPbP3/7X3/6+u30m9/8Kqiw+6hdzla2XsC70VLWMPfR0tagdM2bbdt8pCy8t/st8rPYQexghxvEFewjVzemaffJeQhmgbJVzhHhTmErhUBFXhSSKBGQKwflGzOeG4SUA21MWEwzIiXJFReW5sXTIFg36DPxK9V/fvSKHTVvZvZW6ofL8Ct+s4MUCRs6PDiEZutFqStjRwtALTlrk7YsrDUe0fyBorNQCGpU0JKcnYFFXd3U29lYBMpSznTBcq85AasCdCoMyzVC1FBQpAR1zmCVOzC6dQFGOceOF9Rx5sNkmX4aLOpP9UxE2nzy/LjUAtLjUwLuRQjlB/Pp3aeYLWQRM5XtyTlBr8bqIWgrpM1Gptc1QF1DG2RPPgq8PxkFgbd1OEQzq3w1+qmHbm2MoVyu2iRe6QH0t4BjwUG4jZ7ttmwoWnaWwbj7ZhJXfrpZKw/2ZlXOe7mawjRxf5pbs8R7Z7l3ksM54k+9WOZy4bl6/ODWJ7gJ/vssLOqRI4eIUQp6EssUyog1BUjsLPdRh1QrmmtlhMkVyYAOlMKUc2S4llo7gZ0BohHBvIs84KzDEnHxYyaK/gIPjwdsr3AEDvCfuMEUEb2XlaL/diecPr7fOg6wiab2vwZoAFzUW3SD5Bkh/jrGJctl+QYM1cpnkniDDx4PaM/QdUGv50RBD844Jsf1sXDnMIprvCfWOZVdGOZ8YWDz6YxefvTHazxHcsHYcDpyAT8HKxUL0zKZWrpV97IbIv70xQOx79Zzubg84Drsu6VT9QMiXFazUqcMeLPqg/fGebK0PeESsGNDoz7vVqrq5ByYXay7Q4u9epGoQrVIVv/x7Z+/61cIti78x+t7oVogn//tq7QW4ea4Y79X+zGoiDPoomnkrU1fJBD4X5O2ynVbBRid56OpuyHh94h4u0J7hHj8NjU4Sg024cjDolqN5DIEioeT95fS07HgoKueUIo5enbEkl/M1PtUPfQi9gP1bSTqXH6cbgtP/25P3iYR8jZBWWJI0ySaGCpEW9AsQW7ZtkRwTkUSPtA9iKrF2hM3RsfWo1oB/DYi0EcRABufzXwgQQ8/ocOQwXG1mg2SS12lAxum8jmrwvK0XzfeBlr6X93GxBGz1tP4bqA9aE/KGEoJCLWcuAIXhbaUYg1KoFAZY9afiUbc+Q03w6zE1GoDVkeOmHMhwHtuAcqw2EEP9lsH6fhWfJo0qyqebbN6HUAQU6ym7BYwzXNOkB/jnvWqOS8N32OP5seX3Rhod/QpUesWS3x3yWH+VHNVRdFmZQ0zrlNyD8DNYJWebCXJ83SkaiDR3/WSxu5yxZi/rE38Gr7flz63z9NSY+mcVT8Bra9Vq3JVe1Wl6/SDVVOfHbbp4mXCsc44lqSEhN+TRXUN34YEbeMTSdT8gg/YPEwD3k4B16HLjo4EkFG/o+7LCUy3js7OlVcXfSbc2ediox9SNUvyAn5s8OCE8E8bArtg6cmCdz3lb3jkckvXGxZuSxDA/tj2JomyfAhJPqrap5EAVgXisduj2K58eOaR1ydzszR1GrOXRT7AMyzKDrs6KDm9hOokZXgBYPIvGKPvNmplTJsZFMujq7xJh+qDGab+QG03pSMCK2oeoZOBEuINuo31EKNZnzvx7BOYKF8mb+1X0U1izcjb0bNROPjmrbLRXD6MyoVfjsYf7OwstUty2F6UenXfjsLm2OiKoetlXd5DY9flYrleTe7DJNtD2Slg4qafzznleYn5XrpdnaEO0sl6Fk1aEPokZEEKybThZUywkfdSvW2p1Knd8SYZadogMGUT/J+tc2IRj5VGcTEN6x568JBL9mfU7vbo020nn3pTDgmohjm09swLt/Oim2nhdlrEm+PtMeL4I+SSWnqltN1jivYIiTi59XY7w3JUhGNDMUFrXc7LgCQ3m9+hsdZW3CTGigTdy7x19TQzwvtnhPfOCO2bUWPj4eH9s8E7s0E7s8FPNhu2fzZs72zoEfjQwzNiOzOiOzNiTzYjun9GdO+MyJEZkcMzojszIjszou3RBxCs+1YdlBzv2E1lA8Roi3w7fSRo32/jmKfjpdVQVDZh9VLIVnKdJI2yc570NcwtRv/JC2aYRWsZBQF3QQK01hkHkgVgsCf3M/LRQcbJXOMcE6QZymieCxICSIywiBhFC5nlGWY6K4RDlGAN8g1piThOyZli2+0FCOFp0luBffKr3UU+mnvbnzbSRS4pQ5hKpKk0OVeZMlbDUGjBNaMZkjgvcpLpwljBiMamKATNMqF5UEXanvannH7XT6L3R7/WIfIUjF4z6uYSIonTQ6KGqu5ch2D6DiYbS73a6de5X/I5uete8+k9eT69JYjj6e4phnMQOb7t4e0Xu+7g0bRwodY54GGPUEE3rVyD7Qn0Zzbh3kEPVXYEHc5kSiT5eoXCC79CoSOBPTlEH4NOHRf+c0hHBAqx6SFPx4y7vNp3pYHlHkVvKSDHJFgZPgNNX18BPPns/SBo6xqM3knyTl//o1I7O0NQZ9KrM411nmxzKFjhO7tDqdOpbB4W+vQO0T1+A8Nq3hxMINVRT5bLAhdO5NoqYsB4NQSLzIKKwDA3zmGWYZVpgowFPcAAG8I0z7Ki4AXB4YTxWdtMJDqxvkPoBuEbhM7cX2rhAZM5nFTHezVu/b6lSbC4xD/epUpqEwFfugN1qIEn35UyUlCbO6mxP8AqbWEcpzQjxlkmdGawpcxo6RAXJMNYY8mIYoUCMWGwlmLfrlRvfbf3pZq1Al17FcJnv+DeVEeB+/eovPPqEcmB9gML6oYT+T2G8TRMYeO7OJSFFZPH/c87P6oquAxnM+u9hjsU7nBBOHM5cS5nRUEsJwRInWcOC2SItVpgShUpHEIcKWwBrbBXOpQqMAkRcVVd21kvoWjvxRYKgW4SApt3DyZgqqyAPjOEC8MVksYpQkXhr6KRKOMkz4l2RCKWK6mIyA0nzEqEKKMMoxCN08Ro2UUVZM0YIYwJoZQxzoXIstxHYkmltAY5AVadl9e3wC2awG1thwZTkGL2g3zYk0h3yKdo4FOp9jQsdNyWiG+u/Zt2AfZtXGwXbSjo6hTVRBG2ywSQsH5xLAb1TzBGEEOOo1yCESfAiONA9pQUPocLFw4TXgCotcgI1/DSyd0kx/s4c8xPEQYWfh4ggVitQ+3weA2PvXm3O2st7Gx0KHTbfukuj50MgkRwjZS/mMMER2qeGSmxAV4nCmQMwjmzgNiOwlrQ3EjGJfXTFcDuHNfJM9cmgu8pAiAmov9id1eS98YVNx0xyUNDg51I6OT4xkhTzdZ7dTyXOWV4zqnBuGDIIhi10hnw50zlIF45LVimtLEgWXMwuTkY5BnWYIITZwocLyhagZZRuekWfqRMJGdfLLN5PggD4BhMZf6Pa1sQBeTllE83ZIUwRY4RtUDLOdAqVi4XUlGYWu4jnYEgidZ9d+4BpfcJtI8nEun9awO8+wZAPfX81KtTwvuS91genn0C9sH8BcEggAEZvblWIFgpRIXWzNIcLDT4BxhdVmAB/2W5UAB7ION9x3O2iJF4YmwvJmr1RFPK6ephGY4LLJezlDn6zT+aEH84tEK6ixb28erHqDGf4tVq6QabTs617usWqVLYW9zVSjp4vJ3QC66EeGEM6aEbYjeeVXXdKr2tcIl7jUnQpGiM+HSAUfnLntbylD56Gft+Nv58JvNNNyyFWGZ/+UYbRTLV6foKL9tgoUuP5b7Cu7P5w6er7ds7jkGl7WYW7oJbrDb7n9FbPE37MK9K1quS9apkvSpZr0rWv6qSdcQfeVHs6OmI0X2SYn/Q6Olw0Xu8FS36OdGULZCuQ7b5wxGVG6I+EleJD8VVikujKmPJTlAlOT+mkrykiEoL2A38GpnCqpxnwJ+td5NZUyhBHAkHljMupJRGGKSBLDTLpdVOFQaRgp4RUdky6fMjKzvejze8/9yQyl25sS+Wcl8PnyMmzw2l3CfNDsRQbnrdjqTc18hOCKWn406Gd/fMXe3ziV8cYxledTh3OrxyUPMxIZYw3NWd9cwgxMI9TZTlwSDLDQR2wywvQM3X+MoT8ZUtYzgWZ7kbYXmPv3iA5QEf+ImQy8OL0x1M22TSnwM32Bh47eOOFTk41ZaMnu75RO3WJGzn0HGJZA7+M14tGUP32oslY+zPjjHb+yQeXO9yjfX3zLswpI39ut98ABPBYo2xEdoZiZ3KrD8WbHwOXe4zBUjQwQjNkHZO+4TPBERQ5jTYaTSTdGCF+QvJy+VqT54f7IyymRQIWvV6nIEWNbKES0YYyxB3spAqJxaqyRwZpxHhCEPvUmF+drwJLiizXGstuCRgI4LeTDIBVo/mBStAihpiMp3nOeXKZfCYawa6pOQElG/M9WknFzqyr14u7stz8kOneueeSb3U2fVuGND2M9+66wXh/exnkoiyDeBpwwP38I5N3fNYx7/q7vTL39eNFyb2M9e0gaD7VMUEjT3xFHtrt7FIXSchMdspidb6Qs8QZ3uqbtKNxdKEKEeFV6gYEnV7bfCA3Dpb4p0t257ANXZStmVMFyC2GKdFAczFJ54XCASYyVhOsCEFBymELVI+uWqmmMwLRAVBOYeueW5eZduXlG1ZkRsjlMpNjnMJzN8DjRiiKM4BYMphQYS1DGOXudynHpQ050wzgLBQwl0oETqM3xEI5F9LtHWRYNtybZuNvAqyn58g64f6HRZgg1q7gqu76H5lgWYG+UCmrXcR79hv7656B5A6h37awRsIh9f4ytf4ytf4ytf4ynPiKxMhnbnn2RLxIQ3RX9FRCMcw0aBpskzZDAgIZz7hsQA1UYT7kYC0KHZK49w7RALUAL4cxyRs/oBpVMtCmqIipCm6JOzhVcW8QMXcuV35xy8B5M6C2hz8O2A/dXVbJapVoKZtGIZ9tSsuBfrORVD7wtt+vlLKhqZ96ua0H/HTyK0XZYC9eLHVP/gfsiOUGyV187whopCcYPqzRdI4/F+GSpTm8vIVo+1b1l+lxUXS4lVFeFURXlWEVxXhJ1QR+nspMR7izo5CqI8fiTWj0MmobW7U7ac0I18T1mTUP1Hybh8qnIgjfc4g78bG3awtBWhwnfFlkRmJYC7Y//L5Y4JjcRPDhDcuy/i1P19yHV70wpjSqYLbymfmGP/GzgFEKx/COALIjEqAy6oDTLxCbhT6DFBJLH78WEoMo49O1GH45dCJY1ereArmx7G8l+Us3r6xN8Bkf+adXsKd42PpDQI69oszvUS0zdtDI66qP8jaCzLPLdufdWliAtTjgYtD+KfozsNo866vjW+yrISU7h9X7SmI8DAZMoeJqqsPMQN+xJeQuAda6GFPB9MdBOpHO/pOQ7x6ivNMT5MdZgTi1sRM8O0Vo8t17dMiJN4y2lQ4hjjruozXN9d2dfPmDWDEm82Hb7Z6/RR3S2fyYQoV7WzvGYbjPHTu5CZbUXf5zFUXcTztcbVOSFWzNltIP9YvFkz87vfiZODfMKFHx2z3BpedhMHcztVPAITU7TEodCM7AIau/Eng0LUWnoCs2ktDvhwoqvWqKc1PQRFtx0eJYjO6Q3SxqfGUIHkCGCi78iAIukI89tXclcsUUL5lVGxVapXhzZtd/jWon3SiUOZfnHGpwn72MlCUh9rvo0a9wfQ9w46FnzXurt3nGngPv5546L2W9ww+YE9AHo+hIcQ/ok46k7nXwEJt8P5xGQK6a/U+NZHMvq6T/hGDLRm9IzrSuvVfH1ZqDptVP/mcogTcmVP7+ovPqUcsF04qfjnZFS69aXXvf6bzasXkzsQ2BV8eC/tc4lJETN8+A9Q2TOQc42hzXODHNl6i1+aJw5JP4WHpinoRvQ3YS/GO5C88pLB2R0b0bss2rO1tGezWLmuZP5ayCPrMxrpJ5k8wjpbltDXce4Et4Y7Q9n10iMSHwyZT+tUZWjvaW9nE7HyjVHPUDuNCNS5+tWXVvGkH0t+KuczmO8XbH2m/HHPpgU7oylkKpXo1HH9aw7FF9e6u3Mvo4OA5Sna2GnHkZGTbQljI7Wtfd7n+ketX45yAO5hwi/AWDrU0muqNYr0LUSl9fIRUj/lL+7wr+liO8a29nAZqPS2X8eP4dAF7TKeu97HGCKCLeNXA0/TKp1751OV8KqLQL4NHeep+Dv6UiPxc3vTEelWyMl6AYhVH8hma1c4UTppij/dJPg3bevUJfymf8IXcawelHsHCNkv5S9Wzdin356NopbGfr2kl1HgqVWvQ3CvjemVcT8K4Hq13vSSm9fSK15DofyLNq/OBvgSnVhrL5/i1dqdxhsP4M7YgD/p6LzIUX7d+n3fr92I7cRd9HmMu9hbwF+vV2kOrB2njxfm12sFf4NpqMeTJvFvDBl+51Su3uphbPd6x9aI41TP4trYI/TCHAmi2O5M+mDeGyPdiIGPoYxfuf17Mq8e0uCN5RuB9bHtyMOa+G15X47mD7k/ExvuEfR6Z4rhTRsoTm8z13F8i2SXV6+ZUDvNItcvcle8EzQ979QLml7/EIVHluSscqfPRCxz79OTRrOxykMvi+ZL2+YBpuzDTyJY3FzC0j93glsuQ9vM1yd9LO43k6mp+img/O2ih0iGD8/ElWlUncPpqfM6p1XU57WdfWZdtI/GI5fgUiQ2jVS4gyMSS2mbCcZ/aJcHUuxTXLm7lbbgyMiFD99wdE4jQiheVD7IVH09t3Iq+1O9O9H/MP92lrD4vEfWZiDXM/35Jfox0FKPVpsLRws2Cx+Maof7w2FV7guP4+blLDoK0rPgwF+uPAEbe8uE6GEUhjd7nzyDl8OldhbHhW8fuxyAIS6qJcRgBd2bCUcYLf/qz4A5TeCoY09Qnzve3HQDXVJk0WZ4LVjiE2fb9GwmL/dnOMira8oe1nfpbZHYP1ylODaOMSZ4bIpEoMp+9X1omKc54BkxSUaYF8HjGZW4UMTniJDMFwoYVOjvOkuKN06c4a6rlcwAfhJtzSmlpBKI0p/5uWUU9Y89cZq0rCsdchqUWLic6hxKOckaEkyALYEkNyjqDo8+en6X1AYr4rEs28Y0TB+cO4K5HKo+olc/3PF0HdWCT0jhiVxsQD12lZNkS8Hj84/ftq+/HN9+Pqe/o+/HV9zGDM7yDCj4ZVMD/+OiT6flfn+Cvd0n5jyePuvazb4es0iFu8Gbs5Hq2Ao4097yiTVQ1uceXqHPBl5HmGBjiD7Nujv4uqdF/rm39MPrRn5H7t9LcjL75zf/41c3o95UavaRJ+ItrF6bSay8owl0MZ46oQ4iQQL3XQNLot7ODncX8+tUOnTA+mDDssjV6vELfZZfb4V8SFDgmpc2BiTpshdKGZ1ZzIbFCGReZylmeFRlSwmhGpORcUA6UjknhOHeb8wrtSdtaOldqYF9AAv8fZzYY3w==
"""


def _digest(data: bytes) -> str:
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def _seed_document() -> dict[str, object]:
    encoded = "".join(_SEED_ZLIB_B64.split())
    raw = zlib.decompress(base64.b64decode(encoded))
    if hashlib.sha256(raw).hexdigest() != _SEED_SHA256:
        raise RuntimeError("owned private-input seed digest mismatch")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise RuntimeError("owned private-input seed is not an object")
    return value


def _slotize(value: object, slot: int) -> object:
    if isinstance(value, dict):
        return {key: _slotize(item, slot) for key, item in value.items()}
    if isinstance(value, list):
        return [_slotize(item, slot) for item in value]
    if not isinstance(value, str):
        return value
    replacements = (
        ("engagement.1", f"engagement.owned.{slot}"),
        ("researcher.1", f"researcher.owned.{slot}"),
        ("identity-graph.1", f"identity-graph.owned.{slot}"),
        ("workflow-graph.1", f"workflow-graph.owned.{slot}"),
        ("surface-graph.1", f"surface-graph.owned.{slot}"),
        ("chain-graph.1", f"chain-graph.owned.{slot}"),
        ("loopback.test", "loopback.invalid"),
    )
    for source, target in replacements:
        value = value.replace(source, target)
    return value


def _policy() -> T40ArmPolicy:
    return T40ArmPolicy(
        model_snapshot_digest=FAULTLOOM_UTILITY_V1_MODEL_DIGEST,
        model_runtime_digest=FAULTLOOM_UTILITY_V1_RUNTIME_DIGEST,
        tool_schema_digest=_digest(b"faultloom.t40.owned.tools.v1"),
        gateway_policy_digest=_digest(b"faultloom.t40.owned.gateway.v1"),
        safety_policy_digest=_digest(b"faultloom.t40.owned.safety.v1"),
        generation_config_digest=_digest(b"faultloom.t40.owned.generation.v1"),
        allowed_tools=("lab.http.get",),
        budget=T40ResourceBudget(
            maximum_input_tokens=1024,
            maximum_output_tokens=256,
            maximum_model_calls=1,
            maximum_tool_dispatches=1,
            timeout_seconds=30,
            cpu_seconds=30,
            maximum_address_space_bytes=2_147_483_648,
            maximum_response_bytes=65_536,
        ),
    )


def _validate_with_production_parser(encoded: bytes, slot: int) -> None:
    policy = _policy()
    text = encoded.decode("ascii")
    request = T40ArmRequest(
        request_id=f"formal.owned-private-input.{slot}",
        arm_id="faultloom",
        run_key="control",
        arm_runtime_digest=faultloom_implementation_digest(),
        case_digest=_digest(f"formal-owned-case-{slot}".encode()),
        private_input_digest=_digest(encoded),
        policy_digest=policy.policy_digest,
        model_snapshot_digest=policy.model_snapshot_digest,
        model_runtime_digest=policy.model_runtime_digest,
        tool_schema_digest=policy.tool_schema_digest,
        gateway_policy_digest=policy.gateway_policy_digest,
        safety_policy_digest=policy.safety_policy_digest,
        generation_config_digest=policy.generation_config_digest,
        budget_digest=policy.budget_digest,
        requested_tools=(),
        private_input=text,
        session_id=f"formal.owned-private-input.session.{slot}",
        evaluator_challenge=hashlib.sha256(f"challenge-{slot}".encode()).hexdigest(),
        allocation_id=f"formal-owned-private-input-{slot}",
        trusted_minimum_sequence=0,
        core_wheel_digest=_digest(b"formal-owned-input-validation-wheel"),
    )
    if canonical_json_bytes(_parse_private(request).model_dump(mode="json")) != encoded:
        raise RuntimeError("production parser changed owned private-input bytes")


def generate_owned_private_input(slot: int) -> bytes:
    """Return one canonical, fully typed formal private input for ``slot`` 1..6."""

    if isinstance(slot, bool) or not isinstance(slot, int) or not _MIN_SLOT <= slot <= _MAX_SLOT:
        raise ValueError("slot must be an integer from 1 through 6")
    document = _slotize(_seed_document(), slot)
    if not isinstance(document, dict):
        raise RuntimeError("slotized private input is not an object")
    document["context"]["live"] = False  # type: ignore[index]
    verify_at = _VERIFY_AT + timedelta(seconds=slot)
    document["context"]["verification_time"] = verify_at.isoformat().replace("+00:00", "Z")  # type: ignore[index]
    retrieval_key = hashlib.sha256(f"faultloom-owned-retrieval-slot-{slot}".encode()).digest()
    document["context"]["retrieval_binding_key_hex"] = retrieval_key.hex()  # type: ignore[index]

    # JSON-mode validation is intentional: the closed document carries JSON
    # arrays, RFC 3339 datetimes, and enum strings, exactly as the arm receives
    # them across its process boundary.
    parsed = T40FaultLoomPrivateInput.model_validate_json(canonical_json_bytes(document))
    state = parsed.context.state
    rebound_state = state.model_copy(
        update={
            "checkpoint_binding_tag": checkpoint_binding_tag_for(
                state.checkpoint,
                engagement_id=state.engagement_id,
                binding_key=retrieval_key,
            )
        }
    )
    parsed = parsed.model_copy(
        update={"context": parsed.context.model_copy(update={"state": rebound_state})}
    )
    encoded = canonical_json_bytes(parsed.model_dump(mode="json"))
    _validate_with_production_parser(encoded, slot)
    return encoded


def generate_all_owned_private_inputs() -> tuple[bytes, ...]:
    """Return all six cases in stable slot order."""

    return tuple(generate_owned_private_input(slot) for slot in range(1, 7))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--slot", type=int, choices=range(1, 7))
    args = parser.parse_args(argv)
    if args.slot is not None:
        sys.stdout.buffer.write(generate_owned_private_input(args.slot) + b"\n")
    else:
        values = [json.loads(item) for item in generate_all_owned_private_inputs()]
        sys.stdout.buffer.write(canonical_json_bytes(values) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
